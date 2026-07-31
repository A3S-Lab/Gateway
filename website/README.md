# A3S Gateway website

This directory contains the dependency-free product website published at
<https://a3s-lab.github.io/Gateway/>. GitHub Pages serves these files directly;
there is no generated or vendored build output.

## Local preview

From this directory, run:

```bash
python3 -m http.server 4173
```

Then open <http://127.0.0.1:4173/>.

## Validation

From the repository root, run:

```bash
python3 website/scripts/check_site.py
node --check website/app.js
```

The checker verifies required deployment files, unique HTML IDs, local asset
references, same-page fragments, manifest JSON, and sitemap XML. The Pages
workflow runs both checks before publishing the exact `website/` directory.
