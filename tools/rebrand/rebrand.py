#!/usr/bin/env python3
"""
nullbyte rebrand engine
-----------------------
Patches the opencode Bun single-file ELF in-place-safe byte-for-byte.

Rules (byte length MUST be preserved or the embedded bundle offsets shift and the
ELF breaks):
  * b"OpenCode" (8) -> b"NullByte" (8)          # display/prose only (verified: 0 identifiers)
  * logo block: 4 string literals replaced, each padded with trailing spaces to its
    EXACT original byte length.

Protected (NOT touched, functional):
  opencode.ai, provider id "opencode", opencode.json, env OPENCODE_*,
  x-opencode-* headers, config/dir paths, $schema.
"""
import sys

NAME_LOWER = "nullbyte"
NAME_DISPLAY = "NullByte"

# 4-row block font: rows = top -> bottom, cells are 3 glyph-cols + 1 space
FONT = {
    "n": ["   ", "█▀▄", "█ █", "█ █"],
    "u": ["   ", "█ █", "█ █", "▀▀▀"],
    "l": ["█  ", "█  ", "█  ", "█  "],
    "b": ["█  ", "█▀▄", "█ █", "▀▀▀"],
    "y": ["   ", "█ █", "▀▀█", " █ "],
    "t": ["█  ", "█▀▀", "▀▀ ", "   "],
    "e": ["   ", "▀▀▀", "█▀▀", "▀▀▀"],
}

# original literal contents (without quotes), for length targets + locating the array
ORIG = [
    "\\u2800                                \\u2584     ",
    "\\u2588\\u2580\\u2580\\u2588 \\u2588\\u2580\\u2580\\u2588 \\u2588\\u2580\\u2580\\u2588 \\u2588\\u2580\\u2580\\u2584 \\u2588\\u2580\\u2580\\u2580 \\u2588\\u2580\\u2580\\u2588 \\u2588\\u2580\\u2580\\u2588 \\u2588\\u2580\\u2580\\u2588",
    "\\u2588  \\u2588 \\u2588  \\u2588 \\u2588\\u2580\\u2580\\u2580 \\u2588  \\u2588 \\u2588    \\u2588  \\u2588 \\u2588  \\u2588 \\u2588\\u2580\\u2580\\u2580",
    "\\u2580\\u2580\\u2580\\u2580 \\u2588\\u2580\\u2580\\u2580 \\u2580\\u2580\\u2580\\u2580 \\u2580  \\u2580 \\u2580\\u2580\\u2580\\u2580 \\u2580\\u2580\\u2580\\u2580 \\u2580\\u2580\\u2580\\u2580 \\u2580\\u2580\\u2580\\u2580",
]


def make_logo_rows(word):
    """Return 4 visual rows for the word, fixed 4-col cells."""
    rows = ["", "", "", ""]
    for ch in word:
        g = FONT[ch]
        for r in range(4):
            rows[r] += g[r] + " "
    return [r.rstrip() for r in rows]


def pad_to(raw: bytes, n: int) -> bytes:
    assert len(raw) <= n, f"art too wide: {len(raw)} > {n}"
    return raw + b" " * (n - len(raw))


def guard_lowercase(d: bytearray):
    """Rename standalone lowercase 'opencode' prose -> 'nullbyte', protecting
    functional spans (domains, paths, provider id, theme id, keys, self-spawn)."""
    # explicit, unambiguous: the CLI scriptName drives the help usage prefix
    d[:] = d.replace(b'.scriptName("opencode")', b'.scriptName("nullbyte")')

    n = 0
    i = 0
    while True:
        i = d.find(b"opencode", i)
        if i < 0:
            break
        prev = d[i - 1] if i > 0 else 0x20
        nxt = d[i + 8] if i + 8 < len(d) else 0x20
        protected = (
            nxt in b"./-_\\@"                     # .ai .json /provider -pkg _x \.ai pkg@ver
            or prev in b"./-_\\"                 # .opencode /opencode x-
            or (prev == 0x22 and nxt == 0x22)    # "opencode" (provider/theme id, self-spawn)
            or (prev == 0x27 and nxt == 0x27)    # 'opencode'
            or nxt == 0x3A                       # opencode: (object key)
            or prev == 0x23                      # "# opencode" (shell rc marker)
            or chr(nxt).isalnum()                # opencodeZen, opencodeGo, ...
            or chr(prev).isalnum()
        )
        if not protected:
            d[i:i + 8] = b"nullbyte"
            n += 1
        i += 8
    return n


def fix_display_hints(d: bytearray):
    """Visible string leaks that guard_lowercase can't reach because the word is
    glued to an ANSI escape / alnum char. All replacements are 8 -> 8 bytes.

    * session session-list "Continue" hint: `opencode -s <id>` -> `nullbyte -s <id>`
    """
    n = 0
    for old, new in ((b"opencode -s ", b"nullbyte -s "),):
        assert len(old) == len(new)
        n += d.count(old)
        d[:] = d.replace(old, new)
    return n


def fix_split_brand(d: bytearray):
    """The sidebar/home footer renders the brand as TWO adjacent literals, so the
    contiguous b"OpenCode" rule never matches it:

        K("\\u2022"), K("Open"), K("Code"), <version>
        S1("\\u2022"), S1("Open"), S1("Code"), app.version

    Both halves are 4 bytes, so the rename is length-preserving. Only these exact
    (unique) sequences are touched — the Effect runtime's `_tag:"Open"` state
    literals and the generic "Open"/"Code" UI labels are left alone.
    """
    pairs = [
        (b'w(X,K("Open")),w(W,k),w(k,K("Code"))', b'w(X,K("Null")),w(W,k),w(k,K("Byte"))'),
        (b'i(F,S1("Open")),i(w,O),i(O,S1("Code"))', b'i(F,S1("Null")),i(w,O),i(O,S1("Byte"))'),
    ]
    n = 0
    for old, new in pairs:
        assert len(old) == len(new), (old, new)
        assert d.count(old) <= 1, f"ambiguous split-brand span: {old!r}"
        n += d.count(old)
        d[:] = d.replace(old, new)
    return n


def find_literals(d: bytes, first: bytes):
    i = d.find(b'"' + first.encode() + b'"')
    if i < 0:
        raise SystemExit("logo array not found")
    spans = []
    j = i
    for _ in range(4):
        assert d[j:j + 1] == b'"', "expected quote"
        k = j + 1
        while d[k] != 0x22:  # "
            k += 1
        spans.append((j, k + 1))
        j = k + 1
        while d[j:j + 1] in (b",", b" "):
            j += 1
    return spans


# ---- split splash logo ({left:[...],right:[...]}) --------------------------
# 4-row font, cells 4 glyph-cols wide + 1 separating space. Rendered by D1()
# which maps "_"/"^"/"~" to colored placeholders; plain blocks render colored.
SPLIT_FONT = {
    "n": ["    ", "█▀▀▄", "█  █", "▀  ▀"],
    "u": ["    ", "█  █", "█  █", "▀▀▀▀"],
    "l": ["█   ", "█   ", "█   ", "█   "],
    "b": ["█   ", "█▀▀▄", "█  █", "▀▀▀▀"],
    "y": ["    ", "█  █", "▀▀▀█", "  ▀ "],
    "t": ["█   ", "█▀▀ ", "█   ", "█   "],
    "e": ["    ", "█▀▀█", "█▀▀▀", "▀▀▀▀"],
}
BLOCK_CHARS = "█▀▄"


def split_rows(word):
    rows = ["", "", "", ""]
    for idx, ch in enumerate(word):
        g = SPLIT_FONT[ch]
        for r in range(4):
            rows[r] += g[r] + (" " if idx < len(word) - 1 else "")
    return rows


def build_split(lword, rword, target_len, gap=False):
    """Serialize {left:[...],right:[...]} to EXACT target_len bytes.

    Grows byte length without changing display width by rewriting chosen ASCII
    spaces as \\u0020 escapes (+5 bytes each) and blocks as \\uXXXX (+3 each).
    """
    lt, rt = split_rows(lword), split_rows(rword)
    if gap:
        lt = [r + " " for r in lt]
    base = '{left:["' + '","'.join(lt) + '"],right:["' + '","'.join(rt) + '"]}'
    need = target_len - len(base.encode("utf-8"))
    assert need >= 0, f"art too big: {-need} over"
    spaces = base.count(" ")
    blocks = sum(base.count(c) for c in BLOCK_CHARS)
    sol = None
    for a in range(min(spaces, need // 5), -1, -1):
        rem = need - 5 * a
        if rem % 3 == 0 and rem // 3 <= blocks:
            sol = (a, rem // 3)
            break
    assert sol, f"cannot hit {target_len} bytes exactly"
    a, b = sol
    s = base
    for _ in range(a):
        s = s.replace(" ", "\\u0020", 1)
    for _ in range(b):
        for ch in BLOCK_CHARS:
            if ch in s:
                s = s.replace(ch, "\\u%04x" % ord(ch), 1)
                break
    assert len(s.encode("utf-8")) == target_len, "byte budget mismatch"
    return s.encode("utf-8")


def patch_split_logos(d: bytearray):
    big = b'{left:["' + b" " * 19 + b'","'
    small = b'{left:["    ","\\u2588\\u2580\\u2580\\u2580"'
    edits = []
    for marker, lw, rw, gap in ((big, "null", "byte", False), (small, "n", "b", True)):
        i = 0
        while True:
            i = d.find(marker, i)
            if i < 0:
                break
            end = d.find(b"]}", i) + 2
            edits.append((i, end, build_split(lw, rw, end - i, gap)))
            i = end
    for i, end, new in sorted(edits, key=lambda x: -x[0]):
        d[i:end] = new
    return len(edits)


def rename_local_paths(d: bytearray):
    """Rename on-disk files/dirs opencode -> nullbyte, keeping the network
    contract intact (opencode.ai, provider id "opencode", x-opencode-* headers,
    npm/brew/scoop package names, i18n keys are all untouched).

    All replacements are byte-for-byte equal length.
    """
    n = 0
    pairs = [
        # Path module: single source of all XDG dirs (config/cache/data/state/log/bin)
        (b'var W="opencode",U=H.join', b'var W="nullbyte",U=H.join'),
        (b'Path.config,"opencode"', b'Path.config,"nullbyte"'),
        (b'L(H,"opencode")', b'L(H,"nullbyte")'),
        (b'join($,".local","share","opencode","auth.json")',
         b'join($,".local","share","nullbyte","auth.json")'),
        (b'join(Z,"opencode","auth.json")', b'join(Z,"nullbyte","auth.json")'),
        (b'join(Q,".local","share","opencode","log")',
         b'join(Q,".local","share","nullbyte","log")'),
        (b'join($,"opencode","gitlab-workflow-model-cache.json")',
         b'join($,"nullbyte","gitlab-workflow-model-cache.json")'),
        (b'join($,"opencode","gitlab-model-configs.json")',
         b'join($,"nullbyte","gitlab-model-configs.json")'),
        (b'join(O.store,"opencode")', b'join(O.store,"nullbyte")'),
        (b'join(O,"opencode")', b'join(O,"nullbyte")'),
        (b'"C:\\\\ProgramData","opencode"', b'"C:\\\\ProgramData","nullbyte"'),
        (b'return"/etc/opencode"', b'return"/etc/nullbyte"'),
        (b'files("opencode",', b'files("nullbyte",'),
        # sqlite database filenames
        (b'"opencode.db"', b'"nullbyte.db"'),
        (b'`opencode-${', b'`nullbyte-${'),
        # shell rc marker + PATH dir
        (b'"# opencode"', b'"# nullbyte"'),
        (b'".opencode"', b'".nullbyte"'),
        (b'.opencode/', b'.nullbyte/'),
        (b'~/.config/opencode', b'~/.config/nullbyte'),
        (b'.opencode-version', b'.nullbyte-version'),
        (b'customize-opencode', b'customize-nullbyte'),
        # self-spawn / self-exec command names
        (b'["opencode","import"', b'["nullbyte","import"'),
        (b'spawn(["opencode",', b'spawn(["nullbyte",'),
        (b'{$0:"opencode",', b'{$0:"nullbyte",'),
        (b'command:"opencode",args:', b'command:"nullbyte",args:'),
        # prose sentence-enders that the ".ai" guard skips
        (b"opencode...", b"nullbyte..."),
        # config filename in prose + literals
        (b'opencode.jsonc', b'nullbyte.jsonc'),
    ]
    for old, new in pairs:
        assert len(old) == len(new), (old, new)
        n += d.count(old)
        d[:] = d.replace(old, new)

    # config filename: opencode.json -> nullbyte.json, but never in a URL
    # (brew formula / scoop bucket both use .../opencode.json)
    i = 0
    while True:
        i = d.find(b"opencode.json", i)
        if i < 0:
            break
        if d[i - 8:i] == b"formula/" or d[i - 7:i] == b"bucket/":
            i += 13
            continue
        d[i:i + 13] = b"nullbyte.json"
        n += 1
        i += 13
    return n


def main():
    src, dst = sys.argv[1], sys.argv[2]
    d = bytearray(open(src, "rb").read())
    orig_len = len(d)

    # 1) display rename (capital brand)
    n1 = d.count(b"OpenCode")
    d = bytearray(bytes(d).replace(b"OpenCode", NAME_DISPLAY.encode()))

    # 2) guarded lowercase rename (prose only)
    n2 = guard_lowercase(d)

    # 2b) display hints guard_lowercase cannot reach (ANSI/alnum-adjacent)
    n2b = fix_display_hints(d)

    # 2c) brand split across two adjacent literals (sidebar/home footer)
    n2c = fix_split_brand(d)

    # 3) help/TUI banner logo (UI.logo array)
    rows = make_logo_rows(NAME_LOWER)
    spans = find_literals(bytes(d), ORIG[0])
    for row_text, (s, e), target in zip(rows, spans, ORIG):
        inner = pad_to(row_text.encode("utf-8"), len(target))
        new = b'"' + inner + b'"'
        assert len(new) == e - s, (len(new), e - s)
        d[s:e] = new

    # 4) split splash logo (left/right halves)
    n3 = patch_split_logos(d)

    # 5) on-disk file/dir names (config, cache, data, state, rc marker)
    n4 = rename_local_paths(d)

    assert len(d) == orig_len, "size changed!"
    open(dst, "wb").write(d)
    print(f"OpenCode->{NAME_DISPLAY}: {n1}")
    print(f"standalone opencode->{NAME_LOWER}: {n2}")
    print(f"display hints patched: {n2b}")
    print(f"split-brand literals patched: {n2c}")
    print(f"logo rows: {rows}")
    print(f"split splash logos patched: {n3}")
    print(f"local path/file renames: {n4}")
    print(f"size preserved: {len(d)}")


if __name__ == "__main__":
    main()
