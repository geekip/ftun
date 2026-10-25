#!/usr/bin/env python3
"""Verify CMake source ownership and negative target boundaries."""

import json
from pathlib import Path
import re
import sys


def fail(message: str) -> None:
    raise SystemExit(f"build target boundary: {message}")


if len(sys.argv) != 4:
    fail("source root, compile_commands.json and target manifest are required")

root = Path(sys.argv[1]).resolve()
commands_path = Path(sys.argv[2])
targets_path = Path(sys.argv[3])
commands = json.loads(commands_path.read_text(encoding="utf-8"))
target_map = {}
for line in targets_path.read_text(encoding="utf-8").splitlines():
    name, separator, value = line.partition("=")
    if not separator or name in target_map:
        fail(f"invalid target manifest line: {line}")
    target_map[name] = value

expected_targets = {
    "core": "ftun_core",
    "shared": "ftun_shared_services",
    "app": "ftun_app",
}
for name, target in expected_targets.items():
    if target_map.get(name) != target:
        fail(f"{name} maps to {target_map.get(name)!r}, expected {target}")
if target_map.get("mesh") != "OFF":
    fail("unimplemented Mesh target is advertised")
if target_map.get("proxy") not in {"OFF", "ftun_proxy"}:
    fail("Proxy target map is invalid")
if target_map.get("lwip") != "OFF" and (
        target_map.get("proxy") == "OFF" or target_map.get("tun") == "OFF"):
    fail("lwIP exists without the Proxy TUN consumer")
if (target_map.get("proxy") != "OFF" and target_map.get("tun") != "OFF") != (
        target_map.get("lwip") != "OFF"):
    fail("Proxy TUN consumer and lwIP target presence diverged")

owners = {}
target_pattern = re.compile(r"CMakeFiles/([^/]+)\.dir/")
for entry in commands:
    source = Path(entry["file"]).resolve()
    try:
        relative = source.relative_to(root).as_posix()
    except ValueError:
        continue
    if not relative.startswith("src/") or not relative.endswith(".c"):
        continue
    match = target_pattern.search(entry.get("output", ""))
    if match is None:
        fail(f"missing target output for {relative}")
    target = match.group(1)
    if target.startswith("ftun-") or target == "ftun":
        continue
    if relative in owners:
        fail(f"{relative} is compiled by both {owners[relative]} and {target}")
    owners[relative] = target

expected_core = {
    "src/core/core.c",
    "src/core/context.c",
    "src/core/service.c",
    "src/core/module_plan.c",
    "src/core/budget.c",
    "src/core/operation.c",
    "src/core/worker.c",
}
actual_core = {source for source, owner in owners.items() if owner == "ftun_core"}
if actual_core != expected_core:
    fail(f"Core source set drifted: {sorted(actual_core ^ expected_core)}")

expected_app = {
    "src/app/runtime.c",
    "src/app/composition/default.c",
    "src/app/cli/dispatch.c",
    "src/app/cli/run.c",
    "src/app/cli/result.c",
    "src/app/cli/check.c",
    "src/app/cli/control.c",
    "src/app/cli/fakeip.c",
    "src/app/cli/version.c",
}
if target_map.get("proxy") != "OFF":
    expected_app.add("src/app/composition/proxy_runtime.c")
actual_app = {source for source, owner in owners.items() if owner == "ftun_app"}
if actual_app != expected_app:
    fail(f"App source set drifted: {sorted(actual_app ^ expected_app)}")
required_app_paths = {
    "src/app/main.c",
    "src/app/cli/cli.h",
    "src/app/cli/internal.h",
    "src/app/api/api.c",
    "src/app/api/api.h",
} | expected_app
required_app_paths.add("src/app/runtime_support.h")
missing_app_paths = {
    path for path in required_app_paths if not (root / path).is_file()
}
if missing_app_paths:
    fail(f"App migration lost paths: {sorted(missing_app_paths)}")
legacy_app_paths = {
    "src/main.c", "src/cli", "src/composition", "src/api",
    "src/app/service_runtime.c",
}
remaining_app_paths = {
    path for path in legacy_app_paths if (root / path).exists()
}
if remaining_app_paths:
    fail(f"legacy App paths remain: {sorted(remaining_app_paths)}")
for path in ("src/app/runtime.c", "src/app/cli/check.c"):
    content = (root / path).read_text(encoding="utf-8")
    if re.search(r'#\s*include\s+"(?:proxy|dns|tun)/', content):
        fail(f"common App host retains concrete module dependency: {path}")
    if re.search(r'FTUN_HAVE_MODULE_(?:PROXY|DNS|TUN|FRS|FAKEIP)', content):
        fail(f"common App host retains module-specific lifecycle branches: {path}")

required_proxy = {
    "src/proxy/service.c",
    "src/proxy/bindings.c",
    "src/proxy/runtime.c",
    "src/proxy/dns/dispatch_adapter.c",
    "src/proxy/dns/runtime_adapter.c",
    "src/proxy/dns/control_path_adapter.c",
    "src/proxy/snapshot.c",
    "src/proxy/runtime_state.c",
    "src/proxy/session.c",
    "src/proxy/route/router.c",
    "src/proxy/inbound/inbound.c",
    "src/proxy/inbound/socks5.c",
    "src/proxy/inbound/mixed.c",
    "src/proxy/outbound/outbound.c",
    "src/proxy/outbound/direct.c",
    "src/proxy/outbound/reject.c",
    "src/proxy/outbound/socks5.c",
    "src/proxy/group/select.c",
    "src/proxy/group/url_test.c",
    "src/proxy/group/health.c",
    "src/proxy/sniff/sniff.c",
    "src/proxy/sniff/tls_sni.c",
    "src/proxy/sniff/http_host.c",
    "src/proxy/dns/resolver_adapter.c",
    "src/proxy/udp/session.c",
}
if target_map.get("tun") != "OFF":
    required_proxy.update({
        "src/proxy/tun/ingress.c",
        "src/proxy/tun/lwip_adapter.c",
    })
actual_proxy = {source for source, owner in owners.items() if owner == "ftun_proxy"}
if target_map.get("proxy") == "OFF":
    if actual_proxy:
        fail(f"Proxy=OFF retained sources: {sorted(actual_proxy)}")
else:
    missing_proxy = required_proxy - actual_proxy
    if missing_proxy:
        fail(f"Proxy target lost sources: {sorted(missing_proxy)}")
proxy_migration_paths = {
    "src/proxy/inbound/anytls.c",
    "src/proxy/inbound/anytls.h",
    "src/proxy/inbound/inbound.h",
    "src/proxy/inbound/mixed.h",
    "src/proxy/inbound/socks5.h",
    "src/proxy/outbound/anytls.c",
    "src/proxy/outbound/anytls.h",
    "src/proxy/outbound/direct.h",
    "src/proxy/outbound/outbound.h",
    "src/proxy/outbound/reject.h",
    "src/proxy/outbound/socks5.h",
    "src/proxy/tun/ingress.h",
    "src/proxy/tun/lwip_adapter.h",
    "src/proxy/tun/lwip_port/lwipopts.h",
    "src/proxy/tun/lwip_port/arch/cc.h",
    "src/proxy/tun/lwip_port/arch/perf.h",
    "src/proxy/group/select.h",
    "src/proxy/group/url_test.h",
    "src/proxy/group/health.h",
    "src/proxy/sniff/sniff.h",
    "src/proxy/sniff/tls_sni.h",
    "src/proxy/sniff/http_host.h",
    "src/proxy/frs/format.h",
    "src/proxy/frs/frs.h",
    "src/proxy/frs/ip.h",
    "src/proxy/frs/domain.h",
    "src/proxy/frs/update.h",
    "src/proxy/state/fakeip_store.h",
    "src/proxy/state/fakeip_store_internal.h",
    "src/proxy/state/fakeip_snapshot.h",
}
missing_proxy_paths = {
    path for path in proxy_migration_paths if not (root / path).is_file()
}
if missing_proxy_paths:
    fail(f"Proxy migration lost paths: {sorted(missing_proxy_paths)}")
remaining_proxy_roots = {
    path for path in (
        "src/inbound", "src/outbound", "src/group", "src/frs", "src/sniff",
        "src/state",
    ) if (root / path).exists()
}
if remaining_proxy_roots:
    fail(f"legacy Proxy roots remain: {sorted(remaining_proxy_roots)}")

required_shared = {
    "src/config/config.c",
    "src/event/event.c",
    "src/network/view.c",
    "src/network/resolver.c",
    "src/transport/path.c",
    "src/transport/control_channel.c",
    "src/transport/carrier.c",
    "src/transport/stream.c",
    "src/dns/control_transport.c",
    "src/platform/system_resolver.c",
    "src/util/buffer.c",
}
actual_shared = {
    source for source, owner in owners.items() if owner == "ftun_shared_services"
}
missing_shared = required_shared - actual_shared
if missing_shared:
    fail(f"shared target lost sources: {sorted(missing_shared)}")

dns_sources = {
    "src/dns/dispatcher.c",
    "src/dns/service.c",
    "src/dns/core_service.c",
    "src/dns/server.c",
    "src/dns/listener.c",
    "src/dns/bootstrap.c",
    "src/dns/cache.c",
    "src/dns/wire.c",
}
actual_dns = {
    source for source, owner in owners.items() if owner == "ftun_module_dns"
}
dns_service_test = [
    entry for entry in commands
    if Path(entry["file"]).resolve() == (root / "tests/dns_service.c").resolve()
]
if target_map.get("dns") == "OFF":
    if actual_dns or dns_service_test:
        fail("DNS=OFF retained independent DNS service sources")
elif actual_dns != dns_sources:
    fail(f"DNS source set drifted: {sorted(actual_dns ^ dns_sources)}")
elif len(dns_service_test) != 1 or "ftun-dns-service-test" not in (
        dns_service_test[0].get("output") or ""):
    fail("DNS build lost the Proxy-free service contract target")

tun_sources = {
    "src/tun/device.c",
    "src/tun/service.c",
    "src/tun/dispatch.c",
    "src/tun/route.c",
    "src/tun/path.c",
    "src/tun/owner.c",
    "src/platform/linux/tun.c",
    "src/platform/linux/interface.c",
    "src/platform/linux/route.c",
    "src/platform/linux/route_async.c",
}
actual_tun = {source for source, owner in owners.items() if owner == "ftun_tun"}
raw_test_present = any(
    Path(entry["file"]).resolve() == (root / "tests/tun_shared.c").resolve()
    for entry in commands
)
path_test_present = any(
    Path(entry["file"]).resolve() == (root / "tests/tun_path.c").resolve()
    for entry in commands
)
route_async_test_present = any(
    Path(entry["file"]).resolve()
    == (root / "tests/platform_linux_route_async.c").resolve()
    for entry in commands
)
owner_test_present = any(
    Path(entry["file"]).resolve() == (root / "tests/tun_owner.c").resolve()
    for entry in commands
)
provider_test_present = any(
    Path(entry["file"]).resolve()
    == (root / "tests/provider_bindings.c").resolve()
    for entry in commands
)
if target_map.get("tun") == "OFF":
    if (actual_tun or any(source in owners for source in tun_sources)
            or raw_test_present or path_test_present or route_async_test_present
            or owner_test_present):
        fail("TUN=OFF retained TUN implementation sources")
elif actual_tun != tun_sources:
    fail(f"TUN source set drifted: {sorted(actual_tun ^ tun_sources)}")
elif target_map.get("proxy") != "OFF" and not raw_test_present:
    fail("TUN build lost the test-only raw-L3 consumer")
elif not path_test_present:
    fail("TUN build lost the packet path contract")
elif not route_async_test_present:
    fail("TUN build lost the asynchronous route transaction contract")
elif not owner_test_present:
    fail("TUN build lost the Composition owner contract")
elif not provider_test_present:
    fail("TUN build lost the test-only Mesh Path provider fixture")

optional_prefixes = {
    "dns": "ftun_module_dns",
    "fakeip": "ftun_module_fakeip",
    "frs": "ftun_module_frs",
}
for module, target in optional_prefixes.items():
    actual = {source for source, owner in owners.items() if owner == target}
    if target_map.get(module) == "OFF" and actual:
        fail(f"{module}=OFF retained sources in {target}")
    if target_map.get(module) != "OFF" and not actual:
        fail(f"{module}=BUILTIN has no sources in {target}")

expected_optional_sources = {
    "fakeip": {
        "src/proxy/dns/fakeip.c",
        "src/proxy/state/fakeip_store.c",
        "src/proxy/state/fakeip_snapshot.c",
    },
    "frs": {
        "src/proxy/frs/format.c",
        "src/proxy/frs/frs.c",
        "src/proxy/frs/ip.c",
        "src/proxy/frs/domain.c",
        "src/proxy/frs/update.c",
    },
}
for module, expected in expected_optional_sources.items():
    if target_map.get(module) == "OFF":
        continue
    target = optional_prefixes[module]
    actual = {source for source, owner in owners.items() if owner == target}
    if actual != expected:
        fail(f"{module} source set drifted: {sorted(actual ^ expected)}")

deferred = {
    "src/app/api/api.c",
    "src/proxy/inbound/anytls.c",
    "src/proxy/outbound/anytls.c",
    "src/protocol/anytls.c",
    "src/protocol/uot.c",
}
present_deferred = deferred & owners.keys()
if present_deferred:
    fail(f"unimplemented sources entered targets: {sorted(present_deferred)}")

private_include = re.compile(r'^\s*#\s*include\s+"(?:proxy|mesh)/')
for source in sorted(expected_core | actual_shared | actual_tun | actual_dns):
    for number, line in enumerate((root / source).read_text(encoding="utf-8").splitlines(), 1):
        if private_include.search(line):
            fail(f"private business include in {source}:{number}")

cmake = (root / "CMakeLists.txt").read_text(encoding="utf-8")
if "FTUN_HAVE_MODULE_MESH" in cmake or "ftun_module_mesh" in cmake:
    fail("unimplemented Mesh build capability exists")
if "add_library(ftun_runtime STATIC ${ftun_runtime_objects})" not in cmake:
    fail("compatibility runtime does not aggregate the layer objects")
dns_contract = re.search(
    r"add_executable\(ftun-dns-service-test(?P<body>.*?)"
    r"add_test\(NAME dns-service-independent-contract",
    cmake,
    re.DOTALL,
)
if dns_contract is None:
    fail("independent DNS service contract is not registered")
dns_contract_body = dns_contract.group("body")
for required in (
    "$<TARGET_OBJECTS:ftun_core>",
    "$<TARGET_OBJECTS:ftun_shared_services>",
    "$<TARGET_OBJECTS:ftun_module_dns>",
):
    if required not in dns_contract_body:
        fail(f"independent DNS service contract omits {required}")
if "ftun_proxy" in dns_contract_body or "ftun_runtime" in dns_contract_body:
    fail("independent DNS service contract links Proxy implementation")

for directory in ("src/network", "src/transport", "src/tun"):
    for header in (root / directory).glob("*.h"):
        if re.search(r'#\s*include\s+"platform/linux/', header.read_text()):
            fail(f"platform implementation leaked into contract: {header.relative_to(root)}")

print("build target boundary: ok")
