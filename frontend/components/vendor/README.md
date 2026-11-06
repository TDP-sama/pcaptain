Third-party files served by the UI itself, so it works without internet access
(they used to load from CDNs). Unmodified except where noted.

| File | Version | Source | License |
| --- | --- | --- | --- |
| `axios.min.js` | 1.7.9 | https://cdn.jsdelivr.net/npm/axios@1.7.9/dist/axios.min.js | MIT |
| `chart.umd.min.js` | 4.4.1 | https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js | MIT |
| `font-awesome/` | 4.7.0 | https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/ | CSS: MIT, font: SIL OFL 1.1 |

`font-awesome.min.css`: the `@font-face` rule lists only the WOFF2 and WOFF
fonts shipped here (the EOT, TTF and SVG variants are for very old browsers).

The IBM Plex fonts still come from Google Fonts; without internet access the
pages fall back to the system fonts named in `base.css`.
