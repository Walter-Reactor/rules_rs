load("@aspect_tools_telemetry_report//:defs.bzl", "TELEMETRY")  # buildifier: disable=load
load("@bazel_lib//lib:repo_utils.bzl", "repo_utils")
load("@bazel_skylib//lib:paths.bzl", "paths")
load("//rs/private:annotations.bzl", "WELL_KNOWN_ANNOTATIONS", "annotation_for", "build_annotation_map", "format_well_known_annotation")
load("//rs/private:cargo_credentials.bzl", "load_cargo_credentials")
load("//rs/private:cfg_parser.bzl", "cfg_matches_expr_for_cfg_attrs", "triple_to_cfg_attrs")
load("//rs/private:crate_git_repository.bzl", "crate_git_repository")
load("//rs/private:crate_path_repository.bzl", "crate_path_repository")
load("//rs/private:crate_repository.bzl", "crate_repository")
load("//rs/private:downloader.bzl", "download_metadata_for_git_crates", "download_sparse_registry_configs", "new_downloader_state", "parse_git_url", "sharded_path", "start_crate_registry_downloads", "start_github_downloads")
load("//rs/private:git_repository.bzl", "git_repository")
load("//rs/private:repository_utils.bzl", "render_select")
load("//rs/private:resolver.bzl", "resolve")
load("//rs/private:semver.bzl", "select_matching_version")
load("//rs/private:toml2json.bzl", "run_toml2json")

def _spoke_repo(hub_name, name, version):
    s = "%s__%s-%s" % (hub_name, name, version)
    if "+" in s:
        s = s.replace("+", "-")
    return s

def _external_repo_for_git_source(remote, commit):
    return remote.replace("/", "_").replace(":", "_").replace("@", "_") + "_" + commit

def _platform(triple):
    return "@rules_rust//rust/platform:" + triple.replace("-musl", "-gnu").replace("-gnullvm", "-msvc")

def _select(items):
    return {k: sorted(v) for k, v in items.items()}

def _add_to_dict(d, k, v):
    existing = d.get(k, [])
    if not existing:
        d[k] = existing
    existing.append(v)

def _fq_crate(name, version):
    return name + "-" + version

def _new_feature_resolutions(package_index, possible_deps, possible_features, platform_triples):
    return struct(
        features_enabled = {triple: set() for triple in platform_triples},
        build_deps = {triple: set() for triple in platform_triples},
        deps = {triple: set() for triple in platform_triples},
        aliases = {},
        package_index = package_index,

        # Following data is immutable, it comes from crates.io + Cargo.lock
        possible_deps = possible_deps,
        possible_features = possible_features,
    )

def _date(ctx, label):
    return
    result = ctx.execute(["gdate", '+"%Y-%m-%d %H:%M:%S.%3N"'])
    print(label, result.stdout)

def _normalize_path(path):
    return path.replace("\\", "/")

def _spec_to_dep_dict_inner(dep, spec, is_build = False):
    if type(spec) == "string":
        dep = {"name": dep}
    else:
        dep = {
            "name": dep,
            "optional": spec.get("optional", False),
            "default_features": spec.get("default_features", spec.get("default-features", True)),
            "features": spec.get("features", []),
        }
        if "package" in spec:
            dep["package"] = spec["package"]

    if is_build:
        dep["kind"] = "build"

    return dep

def _spec_to_dep_dict(dep, spec, annotation, workspace_cargo_toml_json, is_build = False):
    if type(spec) == "dict" and spec.get("workspace") == True:
        workspace = workspace_cargo_toml_json.get("workspace")
        if not workspace and annotation.workspace_cargo_toml != "Cargo.toml":
            fail("""

ERROR: `crate.annotation` for `{name}` has a `workspace_cargo_toml` pointing to a Cargo.toml without a `workspace` section. Please correct it in your MODULE.bazel!
Make sure you point to the `Cargo.toml` of the workspace, not of `{name}`!"

""".format(name = annotation.crate))

        inherited = _spec_to_dep_dict_inner(
            dep,
            workspace["dependencies"][dep],
            is_build,
        )

        extra_features = spec.get("features")
        if extra_features:
            inherited["features"] = sorted(set(extra_features + inherited.get("features", [])))

        if spec.get("optional"):
            inherited["optional"] = True

        if spec.get("package"):
            inherited["package"] = spec["package"]

        return inherited
    return _spec_to_dep_dict_inner(dep, spec, is_build)

# Internal rustc placeholder crates that should be filtered from dependencies.
_RUSTC_INTERNAL_CRATES = [
    "rustc-std-workspace-alloc",
    "rustc-std-workspace-core",
    "rustc-std-workspace-std",
]

def _parse_dependencies_from_cargo_toml(cargo_toml_json, annotation, workspace_cargo_toml_json):
    """Parse dependencies and build-dependencies from a Cargo.toml.

    Args:
        cargo_toml_json: Parsed Cargo.toml as a dict.
        annotation: The crate annotation containing workspace info.
        workspace_cargo_toml_json: Parsed workspace Cargo.toml for inheritance.

    Returns:
        A list of dependency dicts.
    """
    dependencies = [
        _spec_to_dep_dict(dep, spec, annotation, workspace_cargo_toml_json)
        for dep, spec in cargo_toml_json.get("dependencies", {}).items()
    ] + [
        _spec_to_dep_dict(dep, spec, annotation, workspace_cargo_toml_json, is_build = True)
        for dep, spec in cargo_toml_json.get("build-dependencies", {}).items()
    ]

    for target, value in cargo_toml_json.get("target", {}).items():
        for dep, spec in value.get("dependencies", {}).items():
            converted = _spec_to_dep_dict(dep, spec, annotation, workspace_cargo_toml_json)
            converted["target"] = target
            dependencies.append(converted)

    return dependencies

def _filter_possible_deps(dependencies):
    """Filter out dev dependencies and internal rustc crates, add default features.

    Args:
        dependencies: List of dependency dicts from _parse_dependencies_from_cargo_toml.

    Returns:
        Filtered list of possible dependencies with default features added.
    """
    possible_deps = [
        dep
        for dep in dependencies
        if dep.get("kind") != "dev" and dep.get("package") not in _RUSTC_INTERNAL_CRATES
    ]

    for dep in possible_deps:
        if dep.get("default_features", True):
            _add_to_dict(dep, "features", "default")

    return possible_deps

def _link_package_dependencies(package, hub_name, versions_by_name, feature_resolutions_by_fq_crate, cfg_match_cache, platform_cfg_attrs, debug = False):
    """Link a package's dependencies to their Bazel targets and feature resolutions.

    Args:
        package: The package dict containing feature_resolutions.
        hub_name: Name of the hub repository.
        versions_by_name: Dict mapping crate names to available versions.
        feature_resolutions_by_fq_crate: Dict mapping fq crate names to feature resolutions.
        cfg_match_cache: Cache for cfg expression matching results.
        platform_cfg_attrs: Platform configuration attributes for matching.
        debug: If True, print debug info when version resolution fails.
    """
    deps_by_name = {}
    for maybe_fq_dep in package.get("dependencies", []):
        idx = maybe_fq_dep.find(" ")
        if idx != -1:
            dep = maybe_fq_dep[:idx]
            resolved_version = maybe_fq_dep[idx + 1:]
            _add_to_dict(deps_by_name, dep, resolved_version)

    for dep in package["feature_resolutions"].possible_deps:
        dep_package = dep.get("package")
        if not dep_package:
            dep_package = dep["name"]

        versions = versions_by_name.get(dep_package)
        if not versions:
            continue
        if len(versions) == 1:
            resolved_version = versions[0]
        else:
            versions = deps_by_name.get(dep_package)
            if not versions:
                continue
            if len(versions) == 1:
                resolved_version = versions[0]
            else:
                resolved_version = select_matching_version(dep["req"], versions)
                if not resolved_version:
                    if debug:
                        print(package["name"], dep_package, versions, dep["req"])
                    continue

        dep_fq = _fq_crate(dep_package, resolved_version)
        dep["bazel_target"] = "@%s//:%s" % (hub_name, dep_fq)
        dep["feature_resolutions"] = feature_resolutions_by_fq_crate[dep_fq]

        target = dep.get("target")
        match = cfg_match_cache.get(target)
        if not match:
            match = cfg_matches_expr_for_cfg_attrs(target, platform_cfg_attrs)

            # TODO(zbarsky): Figure out how to do this optimization safely.
            #if len(match) == len(platform_cfg_attrs):
            #    match = match_all
            cfg_match_cache[target] = match
        dep["target"] = set(match)

def _generate_hub_and_spokes(
        mctx,
        hub_name,
        annotations,
        cargo_path,
        cargo_lock_path,
        all_packages,
        sparse_registry_configs,
        platform_triples,
        cargo_credentials,
        cargo_config,
        validate_lockfile,
        generate_path_deps,
        path_deps_exclude,
        debug,
        generate_path_deps = False,
        path_deps_exclude = [],
        dry_run = False):
    """Generates repositories for the transitive closure of the Cargo workspace.

    Args:
        mctx (module_ctx): The module context object.
        hub_name (string): name
        annotations (dict): Annotation tags to apply.
        cargo_path (path): Path to hermetic `cargo` binary.
        cargo_lock_path (path): Cargo.lock path
        all_packages: list[package]: from cargo lock parsing
        sparse_registry_configs: dict[source, sparse registry config]
        platform_triples (list[string]): Triples to resolve for
        cargo_credentials (dict): Mapping of registry to auth token.
        cargo_config (label): .cargo/config.toml file
        validate_lockfile (bool): If true, validte we have appropriate versions in Cargo.lock
        generate_path_deps (bool): If true, generate repository rules for path dependencies.
        path_deps_exclude (list[string]): Crate names to exclude from path dep generation.
        debug (bool): Enable debug logging
        generate_path_deps (bool): If true, generate repos for local path dependencies.
        path_deps_exclude (list[string]): Crate names to exclude from path dep generation.
        dry_run (bool): Run all computations but do not create repos. Useful for benchmarking.
    """
    _date(mctx, "start")

    mctx.report_progress("Reading workspace metadata")
    result = mctx.execute(
        [cargo_path, "metadata", "--no-deps", "--format-version=1", "--quiet"],
        working_directory = str(mctx.path(cargo_lock_path).dirname),
    )
    if result.return_code != 0:
        fail(result.stdout + "\n" + result.stderr)
    cargo_metadata = json.decode(result.stdout)

    _date(mctx, "parsed cargo metadata")

    existing_facts = getattr(mctx, "facts", {}) or {}
    facts = {}

    # Split workspace members into those that get generated repos vs manual BUILD files
    all_workspace_members = [p for p in all_packages if "source" not in p]

    def _should_generate_path_dep(pkg):
        if not generate_path_deps:
            return False
        return pkg["name"] not in path_deps_exclude

    workspace_members_generated = [p for p in all_workspace_members if _should_generate_path_dep(p)]
    workspace_members = [p for p in all_workspace_members if not _should_generate_path_dep(p)]

    # Track names of generated path deps for dependency resolution
    generated_path_dep_names = {p["name"]: p for p in workspace_members_generated}

    packages = [p for p in all_packages if p.get("source")]

    platform_cfg_attrs = [triple_to_cfg_attrs(triple, [], []) for triple in platform_triples]

    mctx.report_progress("Computing dependencies and features")

    feature_resolutions_by_fq_crate = dict()

    # TODO(zbarsky): Would be nice to resolve for _ALL_PLATFORMS instead of per-triple, but it's complicated.
    cfg_match_cache = {None: platform_triples}

    versions_by_name = dict()
    for package_index in range(len(packages)):
        package = packages[package_index]
        name = package["name"]
        version = package["version"]
        source = package["source"]

        _add_to_dict(versions_by_name, name, version)

        if source.startswith("sparse+"):
            key = name + "_" + version
            fact = existing_facts.get(key)
            if fact:
                facts[key] = fact
                fact = json.decode(fact)
            else:
                package["download_token"].wait()

                # TODO(zbarsky): Should we also dedupe this parsing?
                metadatas = mctx.read(name + ".jsonl").strip().split("\n")
                for metadata in metadatas:
                    metadata = json.decode(metadata)
                    if metadata["vers"] != version:
                        continue

                    features = metadata["features"]

                    # Crates published with newer Cargo populate this field for `resolver = "2"`.
                    # It can express more nuanced feature dependencies and overrides the keys from legacy features, if present.
                    features.update(metadata.get("features2", {}))

                    dependencies = metadata["deps"]

                    for dep in dependencies:
                        if dep["default_features"]:
                            dep.pop("default_features")
                        if not dep["features"]:
                            dep.pop("features")
                        if not dep["target"]:
                            dep.pop("target")
                        if dep["kind"] == "normal":
                            dep.pop("kind")
                        if not dep["optional"]:
                            dep.pop("optional")

                    fact = dict(
                        features = features,
                        dependencies = dependencies,
                    )

                    # Nest a serialized JSON since max path depth is 5.
                    facts[key] = json.encode(fact)
        else:
            key = source + "_" + name
            fact = existing_facts.get(key)
            if fact:
                facts[key] = fact
                fact = json.decode(fact)
            else:
                annotation = annotation_for(annotations, name, package["version"])
                info = package.get("member_crate_cargo_toml_info")
                if info:
                    # TODO(zbarsky): These tokens got enqueues last, so this can bottleneck
                    # We can try a bit harder to interleave things if we care.
                    info.token.wait()
                    workspace_cargo_toml_json = package["workspace_cargo_toml_json"]
                    cargo_toml_json = run_toml2json(mctx, info.path)
                else:
                    cargo_toml_json = package["cargo_toml_json"]
                    workspace_cargo_toml_json = package.get("workspace_cargo_toml_json")
                strip_prefix = package.get("strip_prefix", "")

                dependencies = _parse_dependencies_from_cargo_toml(cargo_toml_json, annotation, workspace_cargo_toml_json)

                if not dependencies and debug:
                    print(name, version, package["source"])

                fact = dict(
                    features = cargo_toml_json.get("features", {}),
                    dependencies = dependencies,
                    strip_prefix = strip_prefix,
                )

                # Nest a serialized JSON since max path depth is 5.
                facts[key] = json.encode(fact)

            package["strip_prefix"] = fact["strip_prefix"]

        possible_features = fact["features"]
        possible_deps = _filter_possible_deps(fact["dependencies"])

        feature_resolutions = _new_feature_resolutions(package_index, possible_deps, possible_features, platform_triples)
        package["feature_resolutions"] = feature_resolutions
        feature_resolutions_by_fq_crate[_fq_crate(name, version)] = feature_resolutions

    # Process generated path deps - parse their Cargo.toml and set up feature resolutions
    repo_root = _normalize_path(cargo_metadata["workspace_root"])
    workspace_cargo_toml_path = mctx.path(cargo_lock_path).dirname.get_child("Cargo.toml")
    workspace_cargo_toml_json = run_toml2json(mctx, workspace_cargo_toml_path)

    for path_dep_index, package in enumerate(workspace_members_generated):
        name = package["name"]
        version = package["version"]

        _add_to_dict(versions_by_name, name, version)

        # Find the manifest_path from cargo_metadata
        # TODO(perf): This is O(n) per path dep. If performance becomes an issue with large
        # workspaces, consider building a lookup dict from cargo_metadata["packages"] upfront.
        # For typical workspaces with few path deps, this is acceptable since it only runs
        # at module extension evaluation time, not build time.
        manifest_path = package.get("manifest_path")
        if not manifest_path:
            # Fallback: look up in cargo_metadata
            for meta_pkg in cargo_metadata["packages"]:
                if meta_pkg["name"] == name and meta_pkg["version"] == version:
                    manifest_path = meta_pkg["manifest_path"]
                    package["manifest_path"] = manifest_path
                    break
            if not manifest_path:
                fail("Could not find manifest_path for generated path dep: %s" % name)

        cargo_toml_json = run_toml2json(mctx, manifest_path)

        annotation = annotation_for(annotations, name, version)

        dependencies = _parse_dependencies_from_cargo_toml(cargo_toml_json, annotation, workspace_cargo_toml_json)

        possible_features = cargo_toml_json.get("features", {})
        # Dev-dependencies are intentionally excluded from dependency resolution.
        # This matches how registry packages are processed (see the sparse+ source handling above)
        # and follows Cargo's behavior where dev-dependencies are only used for tests/examples.
        possible_deps = _filter_possible_deps(dependencies)

        # Use index after packages list so resolve() can access both
        feature_resolutions = _new_feature_resolutions(len(packages) + path_dep_index, possible_deps, possible_features, platform_triples)
        package["feature_resolutions"] = feature_resolutions
        feature_resolutions_by_fq_crate[_fq_crate(name, version)] = feature_resolutions

    # Combined list for resolve() - packages first, then generated path deps
    all_resolvable_packages = packages + workspace_members_generated

    for package in packages:
        _link_package_dependencies(package, hub_name, versions_by_name, feature_resolutions_by_fq_crate, cfg_match_cache, platform_cfg_attrs, debug = True)

    # Link dependencies for generated path deps
    for package in workspace_members_generated:
        _link_package_dependencies(package, hub_name, versions_by_name, feature_resolutions_by_fq_crate, cfg_match_cache, platform_cfg_attrs)

    _date(mctx, "set up resolutions")

    workspace_fq_deps = _compute_workspace_fq_deps(workspace_members + workspace_members_generated, versions_by_name)

    workspace_dep_versions_by_name = {}

    # Only files in the current Bazel workspace can/should be watched, so check where our manifests are located.
    watch_manifests = cargo_lock_path.repo_name == ""

    # Set initial set of features from Cargo.tomls
    for package in cargo_metadata["packages"]:
        if watch_manifests:
            mctx.watch(package["manifest_path"])

        fq_deps = workspace_fq_deps[package["name"]]

        for dep in package["dependencies"]:
            source = dep["source"]
            if not source:
                continue

            dep_name = dep["name"]

            if validate_lockfile and source.startswith("registry+"):
                req = dep["req"]
                fq = fq_deps.get(dep_name)
                if req and fq:
                    locked_version = fq[len(dep_name) + 1:]
                    if not select_matching_version(req, [locked_version]):
                        fail(("ERROR: Cargo.lock out of sync: %s requires %s %s but Cargo.lock has %s.\n\n" +
                              "If this is incorrect, please set `validate_lockfile = False` in `crate.from_cargo`\n" +
                              "and file a bug at https://github.com/dzbarsky/rules_rs/issues/new") % (
                            package["name"],
                            dep_name,
                            req,
                            locked_version,
                        ))

            features = dep["features"]
            if dep["uses_default_features"]:
                features.append("default")

            dep_fq = fq_deps[dep_name]
            dep["bazel_target"] = "@%s//:%s" % (hub_name, dep_fq)
            feature_resolutions = feature_resolutions_by_fq_crate[dep_fq]

            versions = workspace_dep_versions_by_name.get(dep_name)
            if not versions:
                versions = set()
                workspace_dep_versions_by_name[dep_name] = versions
            versions.add(dep_fq)

            target = dep.get("target")
            match = cfg_match_cache.get(target)
            if not match:
                match = cfg_matches_expr_for_cfg_attrs(target, platform_cfg_attrs)

                # TODO(zbarsky): Figure out how to do this optimization safely.
                #if len(match) == len(platform_cfg_attrs):
                #    match = match_all
                cfg_match_cache[target] = match

            for triple in match:
                feature_resolutions.features_enabled[triple].update(features)

    # Add generated path deps to workspace_dep_versions_by_name so they get short hub aliases
    for package in workspace_members_generated:
        name = package["name"]
        version = package["version"]
        fq = _fq_crate(name, version)
        versions = workspace_dep_versions_by_name.get(name)
        if not versions:
            versions = set()
            workspace_dep_versions_by_name[name] = versions
        versions.add(fq)

    # Set initial set of features from annotations
    for crate, annotation_versions in annotations.items():
        for version_key, annotation in annotation_versions.items():
            target_versions = versions_by_name.get(crate, [])
            if version_key != "*":
                if version_key not in target_versions:
                    continue
                target_versions = [version_key]
            if not annotation.crate_features:
                continue
            for version in target_versions:
                features_enabled = feature_resolutions_by_fq_crate[_fq_crate(crate, version)].features_enabled
                for triple in platform_triples:
                    features_enabled[triple].update(annotation.crate_features)

    _date(mctx, "set up initial deps!")

    resolve(mctx, all_resolvable_packages, feature_resolutions_by_fq_crate, debug)

    # Validate that we aren't trying to enable any `dep:foo` features that were not even in the lockfile.
    for package in packages:
        feature_resolutions = package["feature_resolutions"]
        features_enabled = feature_resolutions.features_enabled

        for dep in feature_resolutions.possible_deps:
            if "bazel_target" in dep:
                continue

            prefixed_dep_alias = "dep:" + dep["name"]

            for triple in platform_triples:
                if prefixed_dep_alias in features_enabled[triple]:
                    fail("Crate %s has enabled %s but it was not in the lockfile..." % (package["name"], prefixed_dep_alias))

    mctx.report_progress("Initializing spokes")

    use_home_cargo_credentials = bool(cargo_credentials)

    for package in packages:
        crate_name = package["name"]
        version = package["version"]
        source = package["source"]

        feature_resolutions = feature_resolutions_by_fq_crate[_fq_crate(crate_name, version)]

        annotation = annotation_for(annotations, crate_name, version)
        well_known_annotation = WELL_KNOWN_ANNOTATIONS.get(crate_name)
        if well_known_annotation and annotation.gen_build_script == "auto":
            print("""
WARNING: A well-known crate annotation exists for {crate}! Apply the following to your MODULE.bazel:

```
{formatted_well_known_annotation}
```

You can disable this warning by configuring your MODULE.bazel like so:

```
crate.annotation(
    crate = "{crate}",
    gen_build_script = "on",
)
```""".format(
                crate = crate_name,
                formatted_well_known_annotation = format_well_known_annotation(crate_name, well_known_annotation),
            ))

        kwargs = dict(
            hub_name = hub_name,
            additive_build_file = annotation.additive_build_file,
            additive_build_file_content = annotation.additive_build_file_content,
            gen_build_script = annotation.gen_build_script,
            build_script_deps = [],
            build_script_deps_select = _select(feature_resolutions.build_deps),
            build_script_data = annotation.build_script_data,
            build_script_data_select = annotation.build_script_data_select,
            build_script_env = annotation.build_script_env,
            build_script_toolchains = annotation.build_script_toolchains,
            build_script_tools = annotation.build_script_tools,
            build_script_tools_select = annotation.build_script_tools_select,
            build_script_env_select = annotation.build_script_env_select,
            rustc_flags = annotation.rustc_flags,
            data = annotation.data,
            deps = annotation.deps,
            deps_select = _select(feature_resolutions.deps),
            aliases = feature_resolutions.aliases,
            gen_binaries = annotation.gen_binaries,
            crate_features = annotation.crate_features,
            crate_features_select = _select(feature_resolutions.features_enabled),
            patch_args = annotation.patch_args,
            patch_tool = annotation.patch_tool,
            patches = annotation.patches,
        )

        repo_name = _spoke_repo(hub_name, crate_name, version)

        if source.startswith("sparse+"):
            checksum = package["checksum"]
            url = sparse_registry_configs[source].format(**{
                "crate": crate_name,
                "version": version,
                "prefix": sharded_path(crate_name),
                "lowerprefix": sharded_path(crate_name.lower()),
                "sha256-checksum": checksum,
            })

            if dry_run:
                continue

            crate_repository(
                name = repo_name,
                url = url,
                strip_prefix = "%s-%s" % (crate_name, version),
                checksum = checksum,
                # The repository will need to recompute these, but this lets us avoid serializing them.
                use_home_cargo_credentials = use_home_cargo_credentials,
                cargo_config = cargo_config,
                source = source,
                **kwargs
            )
        else:
            remote, commit = parse_git_url(source)

            strip_prefix = package.get("strip_prefix")
            workspace_cargo_toml = annotation.workspace_cargo_toml
            if workspace_cargo_toml != "Cargo.toml":
                strip_prefix = workspace_cargo_toml.removesuffix("Cargo.toml") + (strip_prefix or "")

            if dry_run:
                continue

            crate_git_repository(
                name = repo_name,
                strip_prefix = strip_prefix,
                git_repo_label = "@" + _external_repo_for_git_source(remote, commit),
                workspace_cargo_toml = annotation.workspace_cargo_toml,
                **kwargs
            )

    # Generate repositories for generated path deps
    for package in workspace_members_generated:
        crate_name = package["name"]
        version = package["version"]
        manifest_path = package["manifest_path"]

        feature_resolutions = feature_resolutions_by_fq_crate[_fq_crate(crate_name, version)]

        annotation = annotation_for(annotations, crate_name, version)

        kwargs = dict(
            hub_name = hub_name,
            additive_build_file = annotation.additive_build_file,
            additive_build_file_content = annotation.additive_build_file_content,
            gen_build_script = annotation.gen_build_script,
            build_script_deps = [],
            build_script_deps_select = _select(feature_resolutions.build_deps),
            build_script_data = annotation.build_script_data,
            build_script_data_select = annotation.build_script_data_select,
            build_script_env = annotation.build_script_env,
            build_script_toolchains = annotation.build_script_toolchains,
            build_script_tools = annotation.build_script_tools,
            build_script_tools_select = annotation.build_script_tools_select,
            build_script_env_select = annotation.build_script_env_select,
            rustc_flags = annotation.rustc_flags,
            data = annotation.data,
            deps = annotation.deps,
            deps_select = _select(feature_resolutions.deps),
            aliases = feature_resolutions.aliases,
            gen_binaries = annotation.gen_binaries,
            crate_features = annotation.crate_features,
            crate_features_select = _select(feature_resolutions.features_enabled),
            patch_args = annotation.patch_args,
            patch_tool = annotation.patch_tool,
            patches = annotation.patches,
        )

        repo_name = _spoke_repo(hub_name, crate_name, version)

        # Use the absolute manifest_path directly
        source_cargo_toml_path = _normalize_path(manifest_path)

        if dry_run:
            continue

        # Provide workspace Cargo.toml for inheriting fields.
        # We use canonical repo syntax (@@) to ensure the label resolves correctly
        # regardless of the apparent repository name in different contexts.
        # The cargo_lock label name may include a directory path (e.g., "path_deps/Cargo.lock"),
        # so we extract the directory to construct the correct Cargo.toml path.
        repo_prefix = "@@" + cargo_lock_path.repo_name if cargo_lock_path.repo_name else "@@"
        cargo_lock_dir = paths.dirname(cargo_lock_path.name)
        if cargo_lock_path.package:
            workspace_cargo_toml_label = repo_prefix + "//" + cargo_lock_path.package + ":Cargo.toml"
        elif cargo_lock_dir:
            workspace_cargo_toml_label = repo_prefix + "//:" + cargo_lock_dir + "/Cargo.toml"
        else:
            workspace_cargo_toml_label = repo_prefix + "//:Cargo.toml"

        crate_path_repository(
            name = repo_name,
            source_cargo_toml = source_cargo_toml_path,
            workspace_cargo_toml = workspace_cargo_toml_label,
            **kwargs
        )

    _date(mctx, "created repos")

    # Generate repositories for local path dependencies if enabled
    path_dep_repos = {}  # name -> (version, spoke_repo)
    if generate_path_deps and not dry_run:
        repo_root = _normalize_path(cargo_metadata["workspace_root"])
        workspace_cargo_toml_label = str(cargo_lock_path).removesuffix("Cargo.lock") + "Cargo.toml"

        for package in cargo_metadata["packages"]:
            crate_name = package["name"]

            # Skip excluded crates
            if crate_name in path_deps_exclude:
                continue

            version = package["version"]
            manifest_path = _normalize_path(package["manifest_path"])

            repo_name = _spoke_repo(hub_name, crate_name, version)

            crate_path_repository(
                name = repo_name,
                hub_name = hub_name,
                source_cargo_toml = manifest_path,
                workspace_cargo_toml = workspace_cargo_toml_label,
                gen_build_script = "auto",
                build_script_deps = [],
                build_script_deps_select = {},
                build_script_data = [],
                build_script_data_select = {},
                build_script_env = {},
                build_script_env_select = {},
                build_script_toolchains = [],
                build_script_tools = [],
                build_script_tools_select = {},
                rustc_flags = [],
                data = [],
                deps = [],
                deps_select = {},
                aliases = {},
                crate_features = [],
                crate_features_select = {},
                gen_binaries = [],
            )

            path_dep_repos[crate_name] = (version, repo_name)

    mctx.report_progress("Initializing hub")

    hub_contents = []
    for name, versions in versions_by_name.items():
        binaries = annotation_for(annotations, name, version).gen_binaries

        for version in versions:
            spoke_repo = _spoke_repo(hub_name, name, version)

            hub_contents.append("""
alias(
    name = "{name}-{version}",
    actual = "@{spoke_repo}//:{name}",
)""".format(name = name, version = version, spoke_repo = spoke_repo))

            for binary in binaries:
                hub_contents.append("""
alias(
    name = "{name}-{version}__{binary}",
    actual = "@{spoke_repo}//:{binary}__bin",
)""".format(name = name, version = version, binary = binary, spoke_repo = spoke_repo))

        workspace_versions = workspace_dep_versions_by_name.get(name)
        if workspace_versions:
            fq = sorted(workspace_versions)[-1]

            hub_contents.append("""
alias(
    name = "{name}",
    actual = ":{fq}",
)""".format(name = name, fq = fq))

            for binary in binaries:
                hub_contents.append("""
alias(
    name = "{name}__{binary}",
    actual = ":{fq}__{binary}",
)""".format(name = name, fq = fq, binary = binary))

    # Add aliases for path dependencies
    for crate_name, (version, spoke_repo) in path_dep_repos.items():
        hub_contents.append("""
alias(
    name = "{name}-{version}",
    actual = "@{spoke_repo}//:{name}",
)""".format(name = crate_name, version = version, spoke_repo = spoke_repo))

    hub_contents.append(
        """
package(
    default_visibility = ["//visibility:public"],
)

filegroup(
    name = "_workspace_deps",
    srcs = [
       %s 
    ],
)""" % ",\n        ".join(['":%s"' % dep for dep in sorted(workspace_dep_versions_by_name.keys())]),
    )

    defs_bzl_contents = \
        """load(":data.bzl", "DEP_DATA")
load("@rules_rs//rs/private:all_crate_deps.bzl", _all_crate_deps = "all_crate_deps")

def aliases(package_name = None):
    dep_data = DEP_DATA.get(package_name or native.package_name())
    if not dep_data:
        return {{}}

    return dep_data["aliases"]

def all_crate_deps(
        normal = False,
        normal_dev = False,
        proc_macro = False,
        proc_macro_dev = False,
        build = False,
        build_proc_macro = False,
        package_name = None,
        cargo_only = False):

    dep_data = DEP_DATA.get(package_name or native.package_name())
    if not dep_data:
        return []

    return _all_crate_deps(
        dep_data,
        normal = normal,
        normal_dev = normal_dev,
        proc_macro = proc_macro,
        proc_macro_dev = proc_macro_dev,
        build = build,
        build_proc_macro = build_proc_macro,
        filter_prefix = {this_repo} if cargo_only else None,
    )

RESOLVED_PLATFORMS = select({{
    {target_compatible_with},
    "//conditions:default": ["@platforms//:incompatible"],
}})
""".format(
            target_compatible_with = ",\n    ".join(['"%s": []' % _platform(triple) for triple in platform_triples]),
            this_repo = repr("@" + hub_name + "//:"),
        )

    _date(mctx, "done")

    repo_root = _normalize_path(cargo_metadata["workspace_root"])

    workspace_dep_stanzas = []
    for package in cargo_metadata["packages"]:
        aliases = {}
        deps = {triple: set() for triple in platform_triples}
        build_deps = {triple: set() for triple in platform_triples}
        dev_deps = {triple: set() for triple in platform_triples}
        package_dir = _normalize_path(package["manifest_path"]).removeprefix(repo_root + "/").removesuffix("/Cargo.toml")
        binaries = {}

        for target in package.get("targets", []):
            if "bin" not in target.get("kind", []):
                continue

            src_path = target.get("src_path")
            if not src_path:
                continue

            entrypoint = _normalize_path(src_path).removeprefix(repo_root + "/")
            if package_dir and entrypoint.startswith(package_dir + "/"):
                entrypoint = entrypoint.removeprefix(package_dir + "/")

            binaries[target["name"]] = entrypoint

        for dep in package["dependencies"]:
            bazel_target = dep.get("bazel_target")
            if not bazel_target:
                dep_name = dep["name"]

                # Check if this is a generated path dep - if so, reference via hub
                if dep_name in generated_path_dep_names:
                    dep_version = generated_path_dep_names[dep_name]["version"]
                    bazel_target = "@%s//:%s-%s" % (hub_name, dep_name, dep_version)
                else:
                    bazel_target = "//" + paths.join(cargo_lock_path.package, _normalize_path(dep["path"]).removeprefix(repo_root + "/"))

                # TODO(zbarsky): check if we actually need this?
                aliases[bazel_target] = dep["name"]

            target = dep.get("target")
            match = cfg_match_cache.get(target)
            if not match:
                match = cfg_matches_expr_for_cfg_attrs(target, platform_cfg_attrs)

                # TODO(zbarsky): Figure out how to do this optimization safely.
                #if len(match) == len(platform_cfg_attrs):
                #    match = match_all
                cfg_match_cache[target] = match

            kind = dep["kind"]
            if kind == "dev":
                target_deps = dev_deps
            elif kind == "build":
                target_deps = build_deps
            else:
                target_deps = deps

            for triple in match:
                target_deps[triple].add(bazel_target)

        bazel_package = paths.join(cargo_lock_path.package, package_dir)

        deps, conditional_deps = render_select([], deps)
        build_deps, conditional_build_deps = render_select([], build_deps)
        dev_deps, conditional_dev_deps = render_select([], dev_deps)

        workspace_dep_stanzas.append("""
    {bazel_package}: {{
        "aliases": {{
            {aliases}
        }},
        "deps": [
            {deps}
        ]{conditional_deps},
        "build_deps": [
            {build_deps}
        ]{conditional_build_deps},
        "dev_deps": [
            {dev_deps}
        ]{conditional_dev_deps},
        "binaries": {{
            {binaries}
        }},
    }},""".format(
            bazel_package = repr(bazel_package),
            aliases = ",\n            ".join(['"%s": "%s"' % kv for kv in sorted(aliases.items())]),
            deps = ",\n            ".join(['"%s"' % d for d in sorted(deps)]),
            conditional_deps = " + " + conditional_deps if conditional_deps else "",
            build_deps = ",\n            ".join(['"%s"' % d for d in sorted(build_deps)]),
            conditional_build_deps = " + " + conditional_build_deps if conditional_build_deps else "",
            dev_deps = ",\n            ".join(['"%s"' % d for d in sorted(dev_deps)]),
            conditional_dev_deps = " + " + conditional_dev_deps if conditional_dev_deps else "",
            binaries = ",\n            ".join(['"%s": "%s"' % kv for kv in sorted(binaries.items())]),
        ))

    data_bzl_contents = "DEP_DATA = {" + "\n".join(workspace_dep_stanzas) + "\n}"

    if dry_run:
        return

    _hub_repo(
        name = hub_name,
        contents = {
            "BUILD.bazel": "\n".join(hub_contents),
            "defs.bzl": defs_bzl_contents,
            "data.bzl": data_bzl_contents,
        },
    )

    return facts

def _compute_package_fq_deps(package, versions_by_name, strict = True):
    possible_dep_fq_crate_by_name = {}

    for maybe_fq_dep in package.get("dependencies", []):
        idx = maybe_fq_dep.find(" ")
        if idx == -1:
            # Only one version
            versions = versions_by_name.get(maybe_fq_dep)
            if not versions:
                if strict:
                    fail("Malformed lockfile?")
                continue
            dep = maybe_fq_dep
            resolved_version = versions[0]
        else:
            dep = maybe_fq_dep[:idx]
            resolved_version = maybe_fq_dep[idx + 1:]

        possible_dep_fq_crate_by_name[dep] = _fq_crate(dep, resolved_version)

    return possible_dep_fq_crate_by_name

def _compute_workspace_fq_deps(workspace_members, versions_by_name):
    workspace_fq_deps = {}

    for workspace_member in workspace_members:
        fq_deps = _compute_package_fq_deps(workspace_member, versions_by_name, strict = False)
        workspace_fq_deps[workspace_member["name"]] = fq_deps

    return workspace_fq_deps

def _crate_impl(mctx):
    # TODO(zbarsky): Kick off `cargo` fetch early to mitigate https://github.com/bazelbuild/bazel/issues/26995
    cargo_path = mctx.path(Label("@rs_rust_host_tools//:bin/cargo"))

    # And toml2json
    toml2json = mctx.path(Label("@toml2json_%s//file:downloaded" % repo_utils.platform(mctx)))

    downloader_state = new_downloader_state()

    packages_by_hub_name = {}

    for mod in mctx.modules:
        if not mod.tags.from_cargo:
            fail("`.from_cargo` is required. Please update %s" % mod.name)

        for cfg in mod.tags.from_cargo:
            annotations = build_annotation_map(mod, cfg.name)
            mctx.watch(cfg.cargo_lock)
            mctx.watch(cfg.cargo_toml)
            cargo_lock = run_toml2json(mctx, cfg.cargo_lock)
            parsed_packages = cargo_lock.get("package", [])
            packages_by_hub_name[cfg.name] = parsed_packages

            # Process git downloads first because they may require a followup download if the repo is a workspace,
            # so we want to enqueue them early so they don't get delayed by 1-shot registry downloads.
            start_github_downloads(mctx, downloader_state, annotations, parsed_packages)

    for mod in mctx.modules:
        for cfg in mod.tags.from_cargo:
            annotations = build_annotation_map(mod, cfg.name)

            if cfg.use_home_cargo_credentials:
                if not cfg.cargo_config:
                    fail("Must provide cargo_config when using cargo credentials")

                cargo_credentials = load_cargo_credentials(mctx, cfg.cargo_config)
            else:
                cargo_credentials = {}

            start_crate_registry_downloads(mctx, downloader_state, annotations, packages_by_hub_name[cfg.name], cargo_credentials, cfg.debug)

    for fetch_state in downloader_state.in_flight_git_crate_fetches_by_url.values():
        fetch_state.download_token.wait()

    download_metadata_for_git_crates(mctx, downloader_state, annotations)

    # TODO(zbarsky): Unfortunate that we block on the download for crates.io even though it's well-known.
    # Should we hardcode it?
    sparse_registry_configs = download_sparse_registry_configs(mctx, downloader_state)

    facts = {}
    direct_deps = []
    direct_dev_deps = []

    for mod in mctx.modules:
        for cfg in mod.tags.from_cargo:
            if mctx.is_dev_dependency(cfg):
                direct_dev_deps.append(cfg.name)
            else:
                direct_deps.append(cfg.name)

            hub_packages = packages_by_hub_name[cfg.name]

            annotations = build_annotation_map(mod, cfg.name)

            if cfg.debug:
                for _ in range(25):
                    _generate_hub_and_spokes(mctx, cfg.name, annotations, cargo_path, cfg.cargo_lock, hub_packages, sparse_registry_configs, cfg.platform_triples, cargo_credentials, cfg.cargo_config, cfg.validate_lockfile, cfg.debug, generate_path_deps = cfg.generate_path_deps, path_deps_exclude = cfg.path_deps_exclude, dry_run = True)

            facts |= _generate_hub_and_spokes(mctx, cfg.name, annotations, cargo_path, cfg.cargo_lock, hub_packages, sparse_registry_configs, cfg.platform_triples, cargo_credentials, cfg.cargo_config, cfg.validate_lockfile, cfg.debug, generate_path_deps = cfg.generate_path_deps, path_deps_exclude = cfg.path_deps_exclude)

    # Lay down the git repos we will need; per-crate git_repository can clone from these.
    git_sources = set()
    for mod in mctx.modules:
        for cfg in mod.tags.from_cargo:
            for package in packages_by_hub_name[cfg.name]:
                source = package.get("source", "")
                if source.startswith("git+"):
                    git_sources.add(source)

    for git_source in git_sources:
        remote, commit = parse_git_url(git_source)

        git_repository(
            name = _external_repo_for_git_source(remote, commit),
            commit = commit,
            remote = remote,
        )

    kwargs = dict(
        root_module_direct_deps = direct_deps,
        root_module_direct_dev_deps = direct_dev_deps,
        reproducible = True,
    )

    if hasattr(mctx, "facts"):
        kwargs["facts"] = facts

    return mctx.extension_metadata(**kwargs)

_from_cargo = tag_class(
    doc = "Generates a repo @crates from a Cargo.toml / Cargo.lock pair.",
    # Ordering is controlled for readability in generated docs.
    attrs = {
        "name": attr.string(
            doc = "The name of the repo to generate",
            default = "crates",
        ),
    } | {
        "cargo_toml": attr.label(
            doc = "The workspace-level Cargo.toml. There can be multiple crates in the workspace.",
        ),
        "cargo_lock": attr.label(),
        "cargo_config": attr.label(),
        "use_home_cargo_credentials": attr.bool(
            doc = "If set, the ruleset will load `~/cargo/credentials.toml` and attach those credentials to registry requests.",
        ),
        "platform_triples": attr.string_list(
            mandatory = True,
            doc = "The set of triples to resolve for. They must correspond to the union of any exec/target platforms that will participate in your build.",
        ),
        "validate_lockfile": attr.bool(
            doc = "If true, fail if Cargo.lock versions don't satisfy Cargo.toml requirements.",
            default = False,
        ),
        "generate_path_deps": attr.bool(
            doc = "Generate repository rules for path dependencies instead of expecting manual BUILD files.",
            default = False,
        ),
        "path_deps_exclude": attr.string_list(
            doc = "Crate names to exclude from path dep generation when generate_path_deps is True.",
            default = [],
        ),
        "debug": attr.bool(),
        "generate_path_deps": attr.bool(
            doc = "If true, generate Bazel repositories for local path dependencies in the Cargo workspace.",
            default = False,
        ),
        "path_deps_exclude": attr.string_list(
            doc = "List of crate names to exclude from path dependency generation. Useful for workspace members with custom BUILD files.",
            default = [],
        ),
    },
)

_relative_label_list = attr.string_list

_annotation = tag_class(
    doc = "A collection of extra attributes and settings for a particular crate.",
    attrs = {
        "crate": attr.string(
            doc = "The name of the crate the annotation is applied to",
            mandatory = True,
        ),
        "version": attr.string(
            doc = "The version of the crate the annotation is applied to. Defaults to all versions.",
            default = "*",
        ),
        "repositories": attr.string_list(
            doc = "A list of repository names specified from `crate.from_cargo(name=...)` that this annotation is applied to. Defaults to all repositories.",
            default = [],
        ),
    } | {
        "additive_build_file": attr.label(
            doc = "A file containing extra contents to write to the bottom of generated BUILD files.",
        ),
        "additive_build_file_content": attr.string(
            doc = "Extra contents to write to the bottom of generated BUILD files.",
        ),
        # "alias_rule": attr.string(
        #     doc = "Alias rule to use instead of `native.alias()`.  Overrides [render_config](#render_config)'s 'default_alias_rule'.",
        # ),
        "build_script_data": _relative_label_list(
            doc = "A list of labels to add to a crate's `cargo_build_script::data` attribute.",
        ),
        # "build_script_data_glob": attr.string_list(
        #     doc = "A list of glob patterns to add to a crate's `cargo_build_script::data` attribute",
        # ),
        "build_script_data_select": attr.string_list_dict(
            doc = "A list of labels to add to a crate's `cargo_build_script::data` attribute. Keys should be the platform triplet. Value should be a list of labels.",
        ),
        # "build_script_deps": _relative_label_list(
        #     doc = "A list of labels to add to a crate's `cargo_build_script::deps` attribute.",
        # ),
        "build_script_env": attr.string_dict(
            doc = "Additional environment variables to set on a crate's `cargo_build_script::env` attribute.",
        ),
        "build_script_env_select": attr.string_dict(
            doc = "Additional environment variables to set on a crate's `cargo_build_script::env` attribute. Key should be the platform triplet. Value should be a JSON encoded dictionary mapping variable names to values, for example `{\"FOO\": \"bar\"}`.",
        ),
        # "build_script_link_deps": _relative_label_list(
        #     doc = "A list of labels to add to a crate's `cargo_build_script::link_deps` attribute.",
        # ),
        # "build_script_proc_macro_deps": _relative_label_list(
        #     doc = "A list of labels to add to a crate's `cargo_build_script::proc_macro_deps` attribute.",
        # ),
        # "build_script_rundir": attr.string(
        #     doc = "An override for the build script's rundir attribute.",
        # ),
        # "build_script_rustc_env": attr.string_dict(
        #     doc = "Additional environment variables to set on a crate's `cargo_build_script::env` attribute.",
        # ),
        "build_script_toolchains": attr.label_list(
            doc = "A list of labels to set on a crates's `cargo_build_script::toolchains` attribute.",
        ),
        "build_script_tools": _relative_label_list(
            doc = "A list of labels to add to a crate's `cargo_build_script::tools` attribute.",
        ),
        "build_script_tools_select": attr.string_list_dict(
            doc = "A list of labels to add to a crate's `cargo_build_script::tools` attribute. Keys should be the platform triplet. Value should be a list of labels.",
        ),
        # "compile_data": _relative_label_list(
        # doc = "A list of labels to add to a crate's `rust_library::compile_data` attribute.",
        # ),
        # "compile_data_glob": attr.string_list(
        # doc = "A list of glob patterns to add to a crate's `rust_library::compile_data` attribute.",
        # ),
        # "compile_data_glob_excludes": attr.string_list(
        # doc = "A list of glob patterns to be excllued from a crate's `rust_library::compile_data` attribute.",
        # ),
        "crate_features": attr.string_list(
            doc = "A list of strings to add to a crate's `rust_library::crate_features` attribute.",
        ),
        "data": _relative_label_list(
            doc = "A list of labels to add to a crate's `rust_library::data` attribute.",
        ),
        # "data_glob": attr.string_list(
        #     doc = "A list of glob patterns to add to a crate's `rust_library::data` attribute.",
        # ),
        "deps": _relative_label_list(
            doc = "A list of labels to add to a crate's `rust_library::deps` attribute.",
        ),
        # "disable_pipelining": attr.bool(
        #     doc = "If True, disables pipelining for library targets for this crate.",
        # ),
        # "extra_aliased_targets": attr.string_dict(
        #     doc = "A list of targets to add to the generated aliases in the root crate_universe repository.",
        # ),
        # "gen_all_binaries": attr.bool(
        #     doc = "If true, generates `rust_binary` targets for all of the crates bins",
        # ),
        "gen_binaries": attr.string_list(
            doc = "As a list, the subset of the crate's bins that should get `rust_binary` targets produced.",
        ),
        "gen_build_script": attr.string(
            doc = "An authoritative flag to determine whether or not to produce `cargo_build_script` targets for the current crate. Supported values are 'on', 'off', and 'auto'.",
            values = ["auto", "on", "off"],
            default = "auto",
        ),
        # "override_target_bin": attr.label(
        #     doc = "An optional alternate target to use when something depends on this crate to allow the parent repo to provide its own version of this dependency.",
        # ),
        # "override_target_build_script": attr.label(
        #     doc = "An optional alternate target to use when something depends on this crate to allow the parent repo to provide its own version of this dependency.",
        # ),
        # "override_target_lib": attr.label(
        #     doc = "An optional alternate target to use when something depends on this crate to allow the parent repo to provide its own version of this dependency.",
        # ),
        # "override_target_proc_macro": attr.label(
        #     doc = "An optional alternate target to use when something depends on this crate to allow the parent repo to provide its own version of this dependency.",
        # ),
        "patch_args": attr.string_list(
            doc = "The `patch_args` attribute of a Bazel repository rule. See [http_archive.patch_args](https://docs.bazel.build/versions/main/repo/http.html#http_archive-patch_args)",
        ),
        "patch_tool": attr.string(
            doc = "The `patch_tool` attribute of a Bazel repository rule. See [http_archive.patch_tool](https://docs.bazel.build/versions/main/repo/http.html#http_archive-patch_tool)",
        ),
        "patches": attr.label_list(
            doc = "The `patches` attribute of a Bazel repository rule. See [http_archive.patches](https://docs.bazel.build/versions/main/repo/http.html#http_archive-patches)",
        ),
        # "proc_macro_deps": _relative_label_list(
        #     doc = "A list of labels to add to a crate's `rust_library::proc_macro_deps` attribute.",
        # ),
        # "rustc_env": attr.string_dict(
        #     doc = "Additional variables to set on a crate's `rust_library::rustc_env` attribute.",
        # ),
        # "rustc_env_files": _relative_label_list(
        #     doc = "A list of labels to set on a crate's `rust_library::rustc_env_files` attribute.",
        # ),
        "rustc_flags": attr.string_list(
            doc = "A list of strings to set on a crate's `rust_library::rustc_flags` attribute.",
        ),
        # "shallow_since": attr.string(
        #     doc = "An optional timestamp used for crates originating from a git repository instead of a crate registry. This flag optimizes fetching the source code.",
        # ),
        "strip_prefix": attr.string(),
        "workspace_cargo_toml": attr.string(
            doc = "For crates from git, the ruleset assumes the (workspace) Cargo.toml is in the repo root. This attribute overrides the assumption.",
            default = "Cargo.toml",
        ),
    },
)

crate = module_extension(
    implementation = _crate_impl,
    tag_classes = {
        "annotation": _annotation,
        "from_cargo": _from_cargo,
    },
)

def _hub_repo_impl(rctx):
    for path, contents in rctx.attr.contents.items():
        rctx.file(path, contents)
    rctx.file("REPO.bazel", "")

_hub_repo = repository_rule(
    implementation = _hub_repo_impl,
    attrs = {
        "contents": attr.string_dict(
            doc = "A mapping of file names to text they should contain.",
            mandatory = True,
        ),
    },
)
