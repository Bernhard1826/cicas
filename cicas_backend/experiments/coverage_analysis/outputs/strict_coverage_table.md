# Table IV — strict native zlint coverage of lintable rules

| Item | CABF | RFC 5280 | Total |
|---|---:|---:|---:|
| zlint cognate lints, total (ref.) | 170 | 122 | 292 |
| of which cert. lints | 164 | 115 | 279 |
| of which CRL lints | 6 | 7 | 13 |
| full (full coverage) | 94 | 71 | 165 |
| uncovered (codegen domain) | 81 | 14 | 95 |
| lintable total | 175 | 85 | 260 |

## Provenance

- DB coverage snapshot: 187 covered / 73 uncovered.
- Strict audit delta: 41 old-covered rows removed from strict coverage; 19 old-uncovered rows restored as strict coverage.
- Strict result: 165 covered / 95 uncovered; 260 = 165 + 95.
