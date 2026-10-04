#!/usr/bin/env python3
"""Render a service template's `${param:name}` placeholders with values.

usage: render_service.py <linux.yaml> <out.yaml> name=value...

The mTLS service templates under packaging/mtls/ take their CA, certificate
and key as file paths, which `fluxor run` cannot yet take as bundle
parameters for a server's client trust; the e2e gates run them as graphs
rendered here. A value replaces a placeholder that is the whole scalar or
part of a quoted string; every placeholder must be given a value.
"""
import re
import sys

src, out, *pairs = sys.argv[1:]
values = dict(p.split("=", 1) for p in pairs)
text = open(src).read()
missing = set(re.findall(r"\$\{param:([a-z0-9_]+)\}", text)) - values.keys()
if missing:
    sys.exit(f"render_service: no value for {sorted(missing)}")
open(out, "w").write(re.sub(r"\$\{param:([a-z0-9_]+)\}", lambda m: values[m.group(1)], text))
