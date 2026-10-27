#!/usr/bin/env python3
"""Approximate static checks for the generated ProVerif files:
 - balanced parentheses per declaration / process
 - every identifier is declared globally or bound earlier in its process
 - function / destructor / event arities match their declarations
 - process-macro calls pass the right number of arguments
"""
import re, sys, glob, os

KW = set("""let in new out if then else event phase process query inj forall reduc fun const
free type equation private data typeConverter channel bitstring attacker""".split())
ID = re.compile(r"[A-Za-z_][A-Za-z0-9_']*")

def strip_comments(t):
    out, depth, i = [], 0, 0
    while i < len(t):
        if t.startswith("(*", i): depth += 1; i += 2; continue
        if t.startswith("*)", i) and depth: depth -= 1; i += 2; continue
        if depth == 0: out.append(t[i])
        i += 1
    return "".join(out)

def split_top(t):
    """Split into top-level items terminated by a '.' outside parentheses."""
    items, cur, depth = [], [], 0
    for i, ch in enumerate(t):
        cur.append(ch)
        if ch == "(": depth += 1
        elif ch == ")": depth -= 1
        elif ch == "." and depth == 0:
            nxt = t[i+1:i+2]
            if nxt == "" or nxt.isspace():
                items.append("".join(cur).strip()); cur = []
    rest = "".join(cur).strip()
    if rest: items.append(rest)
    return items

def args_of(s, start):
    """Given s[start] == '(', return (list_of_arg_strings, end_index)."""
    depth, cur, args = 0, [], []
    for j in range(start, len(s)):
        ch = s[j]
        if ch == "(":
            depth += 1
            if depth == 1: continue
        elif ch == ")":
            depth -= 1
            if depth == 0:
                a = "".join(cur).strip()
                if a or args: args.append(a)
                return args, j
        elif ch == "," and depth == 1:
            args.append("".join(cur).strip()); cur = []; continue
        cur.append(ch)
    return None, len(s)

def lint(path):
    errs = []
    t = strip_comments(open(path).read())
    if t.count("(") != t.count(")"):
        errs.append(f"unbalanced parentheses: {t.count('(')} '(' vs {t.count(')')} ')'")
    items = split_top(t)
    glob_names, arity, macros = {"c"}, {}, {}
    for it in items:
        m = re.match(r"type\s+(\w+)", it)
        if m: glob_names.add(m.group(1)); continue
        m = re.match(r"(const|free)\s+([\w\s,]+?)\s*:", it)
        if m:
            for n in m.group(2).split(","): glob_names.add(n.strip())
            continue
        m = re.match(r"(fun|event)\s+(\w+)\s*\(([^)]*)\)", it)
        if m:
            glob_names.add(m.group(2))
            arity[m.group(2)] = len([a for a in m.group(3).split(",") if a.strip()])
            continue
        m = re.match(r"reduc\s+forall[^;]*;\s*(\w+)\s*\(", it)
        if m:
            name = m.group(1); glob_names.add(name)
            a, _ = args_of(it, it.index("(", it.index(name)))
            arity[name] = len(a); continue
        m = re.match(r"let\s+(\w+)\s*(\(([^=]*)\))?\s*=", it)
        if m and not it.startswith("let (") :
            macros[m.group(1)] = len([a for a in (m.group(3) or "").split(",") if a.strip()])
            glob_names.add(m.group(1))
    for it in items:
        if it.startswith("let ") and re.match(r"let\s+\w+\s*(\(|=)", it):
            m = re.match(r"let\s+(\w+)\s*(\(([^=]*)\))?\s*=", it)
            bound = set(n.split(":")[0].strip() for n in (m.group(3) or "").split(",") if n.strip())
            body = it[m.end():]; where = m.group(1)
        elif it.startswith("process"):
            bound, body, where = set(), it[len("process"):], "process"
        elif it.startswith("query"):
            body = it[len("query"):]
            qv = body.split(";")[0] if ";" in body else ""
            bound = set(n.split(":")[0].strip() for n in qv.split(",") if ":" in n)
            body = body.split(";", 1)[1] if ";" in body else body
            where = "query"
        else:
            continue
        toks = list(ID.finditer(body))
        for k, tk in enumerate(toks):
            name = tk.group(0); pos = tk.start()
            before = body[:pos].rstrip(); after = body[tk.end():].lstrip()
            if name in KW or name in glob_names:
                pass
            elif before.endswith("new") or after.startswith(":") and not after.startswith(":="):
                bound.add(name); continue
            elif re.search(r"let\s*$", before) and after.startswith("="):
                bound.add(name); continue
            elif name not in bound:
                ctx = body[max(0,pos-40):pos+40].replace("\n", " ")
                errs.append(f"[{where}] unbound identifier '{name}' near: ...{ctx}...")
            # arity checks for function / event / macro application
            if after.startswith("(") and name in (arity.keys() | macros.keys()):
                a, _ = args_of(body, body.index("(", tk.end()))
                want = arity.get(name, macros.get(name))
                if a is not None and len(a) != want:
                    errs.append(f"[{where}] '{name}' applied to {len(a)} args, declared with {want}")
    return errs

bad = 0
for f in sorted(glob.glob(os.path.join(sys.argv[1], "*.pv"))):
    e = lint(f)
    status = "OK" if not e else f"{len(e)} issue(s)"
    print(f"{os.path.basename(f):38s} {status}")
    for x in e[:12]: print("    ", x)
    bad += bool(e)
sys.exit(1 if bad else 0)
