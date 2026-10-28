#!/usr/bin/env python3
"""Verify the source-level Core/Proxy ownership boundary."""

from pathlib import Path
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"core/proxy boundary: {message}")


root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd()
core = root / "src" / "core"
proxy = root / "src" / "proxy"

required = (
    root / "src" / "app" / "composition" / "default.c",
    root / "src" / "app" / "runtime.c",
    core / "context.c",
    core / "context.h",
    core / "service.c",
    core / "service.h",
    core / "module_plan.c",
    core / "module_plan.h",
    proxy / "service.c",
    proxy / "service.h",
    proxy / "runtime.c",
    proxy / "runtime.h",
    proxy / "engine_internal.h",
    proxy / "runtime_state.h",
    root / "src" / "dns" / "service.c",
    root / "src" / "dns" / "service.h",
    root / "src" / "dns" / "core_service.c",
    root / "src" / "dns" / "core_service.h",
    proxy / "snapshot.c",
    proxy / "session.c",
    proxy / "route" / "router.c",
    proxy / "route" / "rule.c",
)
for path in required:
    if not path.is_file():
        fail(f"missing extracted source: {path.relative_to(root)}")

removed = (
    core / "engine.c",
    core / "engine.h",
    core / "engine_dns.c",
    core / "engine_dns.h",
    core / "runtime.c",
    core / "runtime.h",
    core / "state.h",
    core / "control_resolver.h",
    core / "http_fetch.h",
    core / "session.c",
    root / "src" / "route",
)
for path in removed:
    if path.exists():
        fail(f"legacy business implementation remains: {path.relative_to(root)}")

private_include = re.compile(r'^\s*#\s*include\s+"(?:proxy|mesh)/')
private_symbol = re.compile(r"\bftun_(?:proxy|mesh)_")
for path in sorted((*core.glob("*.c"), *core.glob("*.h"))):
    text = path.read_text(encoding="utf-8")
    for number, line in enumerate(text.splitlines(), 1):
        if private_include.search(line):
            fail(f"private include in {path.relative_to(root)}:{number}")
        if private_symbol.search(line):
            fail(f"private symbol in {path.relative_to(root)}:{number}")

composition = (root / "src" / "app" / "composition" / "default.c").read_text()
if "ftun_core_create_with_service" not in composition or \
        "ftun_default_catalog" not in composition or \
        "&ftun_proxy_service" not in composition:
    fail("default composition does not register the Proxy service")

service_header = (core / "service.h").read_text()
for token in ("plan_prepare", "prepare", "activate", "reload_commit",
              "run_once", "wakeup", "quiesce", "drain_until",
              "stop_until", "destroy_until"):
    if token not in service_header:
        fail(f"generic service lifecycle is missing {token}")

runtime = (proxy / "engine_internal.h").read_text()
for token in ("struct ftun_proxy_runtime", "ftun_proxy_runtime_listener_t",
              "ftun_proxy_runtime_flow_t", "ftun_proxy_runtime_udp_slot_t"):
    if token not in runtime:
        fail(f"ProxyRuntime does not own {token}")

print("core/proxy boundary: ok")
