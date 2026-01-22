"""Repository rule for generating Bazel repositories from local path dependencies.

This rule creates a Bazel repository from a local Rust crate by symlinking its
contents. Symlinks are used (not copies), meaning changes to source files are
reflected immediately without needing to re-fetch the repository.

If the source crate has an existing BUILD.bazel or BUILD file, it will be
symlinked and used. Otherwise, a BUILD.bazel file will be generated based on
the crate's Cargo.toml.
"""

load("@bazel_tools//tools/build_defs/repo:utils.bzl", "patch")
load(":repository_utils.bzl", "common_attrs", "generate_build_file")
load(":toml2json.bzl", "run_toml2json")

_INHERITABLE_FIELDS = [
    "version",
    "edition",
    "description",
    "homepage",
    "repository",
    "license",
    "license_file",
    "rust_version",
    "readme",
]

def _crate_path_repository_impl(rctx):
    # source_cargo_toml expects an absolute path string to the crate's Cargo.toml.
    # This is provided by the module extension which reads it from cargo metadata.
    source_path = rctx.path(rctx.attr.source_cargo_toml).dirname

    # Check if source has an existing BUILD file
    has_build_bazel = source_path.get_child("BUILD.bazel").exists
    has_build = source_path.get_child("BUILD").exists

    # Symlink source directory contents.
    # BUILD files are conditionally symlinked: if the source provides its own BUILD file,
    # we use it; otherwise we exclude BUILD files here and generate one below.
    # This allows crates to provide custom Bazel configuration while still supporting
    # automatic BUILD file generation for crates that don't.
    for item in source_path.readdir():
        if item.basename == "BUILD.bazel" and has_build_bazel:
            rctx.symlink(item, item.basename)
        elif item.basename == "BUILD" and has_build:
            rctx.symlink(item, item.basename)
        elif item.basename not in ["BUILD.bazel", "BUILD"]:
            rctx.symlink(item, item.basename)

    patch(rctx)

    # Only generate BUILD.bazel if source doesn't have one
    if not has_build_bazel and not has_build:
        cargo_toml = run_toml2json(rctx, "Cargo.toml")

        # Handle workspace inheritance if workspace_cargo_toml is provided
        if rctx.attr.workspace_cargo_toml:
            workspace_cargo_toml = run_toml2json(rctx, rctx.attr.workspace_cargo_toml)
            workspace_package = workspace_cargo_toml.get("workspace", {}).get("package")
            if workspace_package:
                crate_package = cargo_toml["package"]
                for field in _INHERITABLE_FIELDS:
                    value = crate_package.get(field)
                    if type(value) == "dict" and value.get("workspace") == True:
                        crate_package[field] = workspace_package.get(field)

        rctx.file("BUILD.bazel", generate_build_file(rctx, cargo_toml))

    return rctx.repo_metadata(reproducible = True)

crate_path_repository = repository_rule(
    implementation = _crate_path_repository_impl,
    attrs = {
        "source_cargo_toml": attr.string(
            mandatory = True,
            doc = "Path to the Cargo.toml of the path dependency (absolute or label string).",
        ),
        "workspace_cargo_toml": attr.label(
            doc = "Label pointing to the workspace Cargo.toml for inheriting fields.",
        ),
        # Note: common_attrs includes `strip_prefix` which is inherited for consistency
        # with other crate repository rules, but it has no effect for path dependencies
        # since we symlink the source directory directly.
    } | common_attrs,
)
