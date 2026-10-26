# Contributing

Open a focused issue and pull request. Report sensitive checker flaws through [SECURITY.md](SECURITY.md). Python 3.10+ suffices; no third-party runtime or test dependencies are needed.

```sh
python -m unittest -v
python http2shell_check.py --help
git diff --check
```

Keep the single-file checker offline and source-backed. Add meaningful behavior tests for affected/fixed boundaries, identities, vendor uncertainty and output protections. Use synthetic inventories and mocks; do not run real target scans or import native decoders. Do not add tests that merely assert prose. Update CLI/schema documentation with implementation changes. Keep private assessment data out of commits.

## Licensing of contributions

By submitting a contribution, you confirm you have the right to submit it. You license it to the public under AGPL-3.0 and grant CompleteTech LLC a perpetual, worldwide, royalty-free, irrevocable license to use, modify, sublicense, and distribute it under any license, including a commercial license. You retain copyright in your contribution. See [LICENSING.md](LICENSING.md).
