# Reproduce the report screenshots

## Source finding in the quickstart

Run the [quickstart](../../README.md#quick-start) and open `demo.html`. The two `source-finding` PNGs show the actual NEXT-02 evidence and fix. They are headless Chromium element screenshots of `section.item.fail` at viewport widths of 390 and 800 CSS pixels in light mode. No report text or styling was changed for the capture.

## Practice site report

`report.png` and `report-mobile.png` are headless Chromium screenshots of a real HTML report from the bundled vulnerable lab. They show the report renderer in this source revision, not a mockup or a published PyPI release. No scan results were edited.

## Run the lab

Install this checkout in a virtual environment, then use its `asa` executable. On macOS or Linux:

```sh
uv venv .venv
uv pip install --python .venv/bin/python .
.venv/bin/asa --version
.venv/bin/asa lab
```

Leave that terminal running. In another terminal, from the same checkout:

```sh
.venv/bin/asa scan http://127.0.0.1:8642 --rate-limit-path /api/login --out .asa/report.html --out .asa/report.json
```

Exit `1` is expected: the lab deliberately has failures. Open `.asa/report.html` in a browser. Stop the lab with **Ctrl-C** when finished. On Windows, use `.venv\Scripts\asa.exe` for the executable.

## What the run observed

The screenshot run used agent-security-audit 0.2.0 from source, on 2026-11-16. The only contacted host was `127.0.0.1`. The generated report recorded:

| Fail | Warn | Error | Manual | Pass | Skip |
|---:|---:|---:|---:|---:|---:|
| 18 | 6 | 0 | 85 | 0 | 17 |

After restarting the lab with `asa lab --mode fixed` and running the same scan, the counts were `0 fail · 0 warn · 0 error · 85 manual · 24 pass · 17 skip`. The manual and skipped checks remain unproven by this local scan.

## Capture the images

Use headless Chromium, light color scheme, device scale factor `1`, with a viewport of **1280 × 960** for `report.png` and **390 × 960** for `report-mobile.png`. Capture the initial viewport with all fixes collapsed. Both images are unmodified browser captures.

The visual direction references [GitHub Primer](https://primer.style/product/components/page-layout/) for restrained hierarchy and status colors, and [Astral's uv documentation](https://docs.astral.sh/uv/) for concise task navigation. No assets were copied from either reference.

A pass means the defense was observed working on this target at this time. It is not a guarantee that the site has no other flaws.
