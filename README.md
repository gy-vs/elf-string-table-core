# ELF codec core

TypeScript library for ELF binary structures.

Run `npm install`, then `npm test` and `npm run build`.

## String tables

`createStringTable(data, offset, size, policy?)` returns a view bounded to its
section: indexes must be `< size`, and a name is only returned if its NUL
terminator lies inside the view (clamped to EOF for truncated sections).
Anything else — out-of-bounds index, missing terminator — yields `null`, never
bytes borrowed from the next section. Index `0` is the empty string per the ELF
spec. `getBytes` returns the raw bytes without decoding.

Invalid UTF-8 is handled by an explicit policy: `'replace'` (default, U+FFFD
via `TextDecoder`) or `'bytes'` (one char per byte).

## Names

- `sectionNames(data)` resolves `sh_name` through the `e_shstrndx` table only.
- `parseSymbols(data)` resolves `st_name` through each symbol section's
  `sh_link` table; unresolvable names stay `null`.
- `symbolIndex(symbols)` builds a name → symbols map; symbols with `null`
  names are never entered into the index.
