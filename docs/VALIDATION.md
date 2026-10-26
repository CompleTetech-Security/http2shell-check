# Validation and example reproduction

The checker and tests need Python 3.10+ only. Run:

```sh
python -m unittest -v
python http2shell_check.py --help
python http2shell_check.py --inventory examples/inventory.json --format json
python http2shell_check.py --pip-list examples/pip-list.json --format csv
python http2shell_check.py --node-inventory examples/node-runtime.json --format json
git diff --check
```

The initial local suite includes 27 unittest methods with parameterized branch/identity cases. It covers every enabled branch boundary, uncertainty, separate copies, parser bounds, output escaping, formula safety, standalone execution in all formats, no network/process calls, input/alias/default-logo protection, atomic failure and interruption behavior. Tests use synthetic data and mocks only. Hosted CI runs the same suite on Linux/Windows/macOS with Python 3.10 and 3.14; the optional collector smoke job is separate. Local tests and hosted CI are distinct evidence.

To regenerate the report, explicitly replace only the synthetic example:

```sh
python http2shell_check.py --inventory examples/inventory.json --format html --output docs/example-report.html --force
```

Screenshots/banner/print PDF were generated with existing Docker image `mcp/playwright` (image revision `2d446f9e1b79886103c79406b81cc5408364487a`). This developer-only tooling is not a runtime/test dependency. With that image already installed, mount the checkout at `/work` and run its Node binary on `/work/tools/render_examples.cjs`; the script uses Playwright packaged inside the image. Example PowerShell command, substituting your absolute checkout path:

```powershell
docker run --rm --init --user root --mount 'type=bind,source=C:\path\to\http2shell-check,target=/work' --entrypoint node mcp/playwright /work/tools/render_examples.cjs
```

The renderer loads local HTML, blocks external requests, captures light/dark/narrow/print screenshots, creates a print PDF and generates the branded banner from HTML with the existing logo. [visual-checks.json](visual-checks.json) records layout widths, six component cards, image loading and no overflow/external requests. Screenshots are viewport previews; the complete report is in [example-report.html](example-report.html) and [example-report.pdf](example-report.pdf).

Model visual inspection reviewed actual light/dark, 390px narrow and print previews, including legibility, wrapping and status labels. This is separate from automated geometry checks and does not constitute a human security or accessibility audit. No clipping was observed in those reviewed views. Examples contain reserved domains and synthetic metadata only.
