#!/usr/bin/env python3
"""Check every TOML block of the security docs against eggrd's config schema, and write each one out
for `edgeguard doctor`.

  python3 check-toml-blocks.py <src/config.rs> <out dir> <file.md|file.toml>...

- Every ```toml block of a markdown file (and every .toml file given) must parse.
- Every key must be a field serde reads in src/config.rs. eggrd ignores unknown keys silently, and
  `doctor` cannot see them either (a misspelt `inspect_header` loads and does nothing), so this is
  the check that catches them.
- Each block is written to <out dir>/NNN.toml with a first-line comment naming its source, for a
  doctor run over the directory. Blocks are written as they stand: a fragment (one section) is a
  complete config with every other section at its default, which is how eggrd reads it, and how the
  corpus says it was validated.

Exits 1 on a block that does not parse or a key that does not exist.
"""
import os
import re
import sys
import tomllib


# Field types that take a TOML table but are not structs of src/config.rs, so their sub-keys cannot
# be checked here. Each entry needs a reason; empty means every table in the docs was verified.
EXTERNAL_TABLE_TYPES = {}


def structs_of(src):
    # Key names this parser does not model: refuse the schema rather than misjudge keys.
    for bad in ("alias =", "rename_all"):
        if bad in src:
            sys.exit(f"src/config.rs uses serde `{bad.rstrip(' =')}`, which check-toml-blocks.py does not model: teach it first")
    structs = {}
    for m in re.finditer(r"pub struct (\w+)(?:<'a>)? \{(.*?)\n\}", src, re.S):
        fields, attrs = {}, []
        for line in m.group(2).split("\n"):
            s = line.strip()
            if s.startswith("#["):
                attrs.append(s)
                continue
            fm = re.match(r"pub (\w+): (.+?),?$", s)
            if fm:
                # Only `skip` and `skip_deserializing` stop serde reading a key; `skip_serializing`
                # and `skip_serializing_if` do not (`\b` fails before the `_` that follows).
                if not any(re.search(r"serde\([^)]*\bskip(_deserializing)?\b", a) for a in attrs):
                    ren = [r.group(1) for r in (re.search(r'rename = "(\w+)"', a) for a in attrs) if r]
                    flat = any("serde(flatten" in a for a in attrs)
                    fields[ren[0] if ren else fm.group(1)] = (fm.group(2), flat)
                attrs = []
            elif s and not s.startswith("//"):
                attrs = []
        structs[m.group(1)] = fields
    return structs


def inner(t):
    t = t.strip()
    for w in ("Vec<", "Option<"):
        if t.startswith(w):
            return inner(t[len(w):-1])
    return t.split("::")[-1]


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    structs = structs_of(open(sys.argv[1], encoding="utf-8").read())

    def keys_of(name):
        out = {}
        for k, (t, flat) in structs.get(name, {}).items():
            out.update(keys_of(inner(t)) if flat else {k: t})
        return out

    errors = []

    def check(obj, name, path):
        allowed = keys_of(name)
        if name == "TargetCfg":  # custom Deserialize: a URL string, or this table
            allowed = {"url": "String", "weight": "u32", "check_host": "String"}
        for k, v in obj.items():
            if k not in allowed:
                errors.append(".".join(path + [k]) + f"  (no such key in {name})")
                continue
            t = allowed[k]
            if "BTreeMap" in t:
                # A map: its keys are data (user names, model names), but a value that is a struct
                # of config.rs has keys of its own, checked like any table.
                vt = inner(t[t.index(",") + 1 : t.rindex(">")])
                if isinstance(v, dict):
                    for mk, mv in v.items():
                        if not isinstance(mv, dict):
                            continue
                        if vt in structs:
                            check(mv, vt, path + [k, mk])
                        elif vt not in EXTERNAL_TABLE_TYPES:
                            errors.append(".".join(path + [k, mk]) + f"  (table of type {vt}, not found in config.rs: sub-keys not verified)")
                continue
            it = inner(t)
            tables = [e for e in (v if isinstance(v, list) else [v]) if isinstance(e, dict)]
            if not tables:
                continue
            if it not in structs:
                # A table whose type this parser could not resolve (defined elsewhere, an enum, a
                # type it does not read): its sub-keys cannot be verified, which is an error, not a
                # pass. A type that is genuinely external goes in EXTERNAL_TABLE_TYPES, with why.
                if it not in EXTERNAL_TABLE_TYPES:
                    errors.append(".".join(path + [k]) + f"  (table of type {it}, not found in config.rs: sub-keys not verified)")
                continue
            for i, e in enumerate(v if isinstance(v, list) else [v]):
                if isinstance(e, dict):
                    check(e, it, path + [k] + ([str(i)] if isinstance(v, list) else []))

    blocks = []
    for f in sys.argv[3:]:
        text = open(f, encoding="utf-8").read()
        if f.endswith(".toml"):
            blocks.append((f, 1, text))
            continue
        for m in re.finditer(r"```toml\n(.*?)```", text, re.S):
            blocks.append((f, text[: m.start()].count("\n") + 1, m.group(1)))

    out = sys.argv[2]
    os.makedirs(out, exist_ok=True)
    for i, (f, line, body) in enumerate(blocks):
        where = f"{os.path.basename(f)}:{line}"
        try:
            obj = tomllib.loads(body)
        except tomllib.TOMLDecodeError as e:
            errors.append(f"{where}: does not parse: {e}")
            continue
        before = len(errors)
        check(obj, "Config", [])
        errors[before:] = [f"{where}: {e}" for e in errors[before:]]
        with open(os.path.join(out, f"{i:03d}.toml"), "w", encoding="utf-8") as o:
            o.write(f"# {where}\n{body}")
    print(f"{len(blocks)} TOML blocks checked against {sys.argv[1]}")
    for e in errors:
        print("ERROR", e)
    sys.exit(1 if errors else 0)


if __name__ == "__main__":
    main()
