# Release checklist

Use this checklist before publishing a release. It describes checks to perform;
it does not assert that they have already been completed.

1. Choose the release version, update `pyproject.toml` and the lockfile, and
   move the relevant entries in `CHANGELOG.md` from Unreleased to that version.
2. Confirm the working tree is clean and review changes for sensitive data.
3. Run the CI checks: the test suite on Linux with Python 3.11, 3.12 and 3.13,
   Ruff, the documented mypy baseline, a MkDocs build, and the package checks.
   The supported Python requirement is 3.11 or newer; the CI matrix does not
   establish compatibility with every newer version or platform.
4. On a clean supported Kali testing VM, install the release candidate and its
   required external tools. Verify `ad-kit --version`, `ad-kit --help`, and
   `ad-kit tools status`; record the OS, Python and external tool versions.
5. In an authorised AD lab, exercise enumeration and representative checks,
   including failures and cleanup. Verify HTML and JSON reports and import a
   SureFormat XML with multiple host services into the target platform.
6. Review documentation, known limitations, dependency licensing and the MIT
   license. Ensure release notes describe behaviour changes and migration steps.
7. Create a version tag matching `pyproject.toml` and publish release notes and
   the intended distribution artefacts. Inspect their contents for sensitive or
   unintended files, and verify installation from the published tag in a clean
   environment.

The current CI lint command ignores existing line-length violations. Strict
mypy currently covers the finding model and JSON and SureFormat exporters,
not the entire codebase; expand both baselines as existing issues are resolved.
