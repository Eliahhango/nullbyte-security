# rebrand

Toolchain that renames the bundled CLI's display strings to NullByte. The CLI is
a single-file Bun ELF, so the brand is patched **byte-for-byte** — every
replacement must be length-preserving or the embedded bundle offsets shift and
the binary breaks.

```bash
./reapply.sh                      # default: ~/.nullbyte/bin/nullbyte
./reapply.sh /path/to/binary
```

Run it after `nullbyte upgrade` overwrites the binary, since the upgrade
restores the upstream brand. `reapply.sh` keeps a pristine copy in
`nullbyte.stock` and no-ops if the target is already rebranded.

## What gets renamed

| Surface | Example |
|---|---|
| Display prose (`OpenCode` → `NullByte`) | banner, help, errors |
| Standalone lowercase prose (`opencode` → `nullbyte`) | only when not part of a path, domain, id or key |
| Split-brand literals | the sidebar/home footer renders the brand as two adjacent literals, so a contiguous match misses it |
| On-disk paths | config, cache, data, state, shell rc marker |

## What is deliberately left alone

Functional identifiers: `opencode.ai`, the provider id `"opencode"`,
`opencode.json`, `OPENCODE_*` env vars, `x-opencode-*` headers, the
`OpencodeClient` SDK class, i18n keys such as `installOpencode`, and the Effect
runtime's `_tag:"Open"` state literals. Renaming any of these breaks the network
contract or the runtime.

## Files

- `rebrand.py` — the patch engine
- `reapply.sh` — idempotent wrapper, safe to run while the binary is in use
- `scrub-key.sh` — removes a leaked API key from config files and the session
  store; reads the key from a file and never prints or embeds it

The binaries are not committed — they are ~185 MB each. See `.gitignore`.
