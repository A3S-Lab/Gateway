# A3S Gateway website

This directory contains the dependency-free product website published at
<https://a3s-lab.github.io/Gateway/>. The Pages workflow stages this directory
with the repository-root `install.sh` and `install.ps1`; there is no generated
or vendored application bundle.

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

The checker verifies required deployment files, repository installers, unique
HTML IDs, local asset references, same-page fragments, manifest JSON, and
sitemap XML. The Pages workflow runs both checks before staging the public
artifact.

## Request-path animation

`assets/request-path-demo.svg` is the editable static source and reduced-motion
fallback. `assets/request-path-demo.gif` is the GitHub- and Pages-safe animated
render. The motion contract lives at
`../assets/readme/request-path-demo-motion.json`.

Regenerate the GIF with the `beautify-github-readme` renderer:

```bash
python3 /path/to/beautify-github-readme/scripts/render_motion_gif.py \
  website/assets/request-path-demo.svg \
  website/assets/request-path-demo.gif \
  --spec assets/readme/request-path-demo-motion.json
```
