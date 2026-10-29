#!/usr/bin/env python3
"""由 schema/ftun.schema.json 生成 docs/configuration.md；不带参数时检查文档与 Schema 一致。
用法：docs_configuration.py [--write] SCHEMA DOCUMENT"""
import json
import sys
from pathlib import Path

HEADER = """# 配置参考

本文由 `schema/ftun.schema.json` 生成（`python3 tests/docs_configuration.py --write schema/ftun.schema.json docs/configuration.md`），
测试 `docs-configuration` 会在 Schema 变化而文档未更新时失败。Schema 只描述结构与取值范围；
字段之间的关系（例如端口冲突、时长大小关系）由 `ftun check -c CONFIG` 校验。

时长写作 `500ms`、`5s`、`5m`、`24h`，不接受 0、负数、小数或无单位。未列出的字段会被拒绝。

"""


def deref(schema, node):
    while isinstance(node, dict) and "$ref" in node:
        target = schema
        for part in node["$ref"].lstrip("#/").split("/"):
            target = target[part]
        extra = {k: v for k, v in node.items() if k != "$ref"}
        node = {**target, **extra}
    return node


def type_text(node):
    kind = node.get("type")
    if isinstance(kind, list):
        kind = "/".join(kind)
    if kind == "array":
        return "数组"
    return {"string": "字符串", "integer": "整数", "boolean": "布尔", "object": "对象",
            "number": "数字", None: "多选一"}.get(kind, str(kind))


def constraints(node):
    parts = []
    if "enum" in node:
        parts.append("取值：" + "、".join(f"`{v}`" for v in node["enum"]))
    if "const" in node:
        parts.append(f"固定为 `{json.dumps(node['const'])}`")
    for key, label in (("minimum", "最小"), ("maximum", "最大"), ("minLength", "最短"),
                       ("maxLength", "最长"), ("minItems", "至少项数"), ("maxItems", "至多项数")):
        if key in node:
            parts.append(f"{label} {node[key]}")
    if "pattern" in node:
        parts.append("格式见 Schema")
    return "；".join(parts)


def default_text(node):
    if "default" not in node:
        return ""
    value = node["default"]
    return "`" + (json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value) + "`"


def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def rows(schema, node, path, required, out, depth=0):
    node = deref(schema, node)
    if depth > 8:
        return
    description = node.get("description", "")
    if path:
        label = path + ("（必填）" if required else "")
        out.append(f"| `{cell(label)}` | {type_text(node)} | {cell(default_text(node))} | "
                   f"{cell(constraints(node))} | {cell(description)} |")
    properties = node.get("properties")
    if properties:
        needed = set(node.get("required", []))
        for name, child in properties.items():
            if name == "$schema":
                continue
            rows(schema, child, f"{path}.{name}" if path else name, name in needed, out, depth + 1)
    if node.get("type") == "array" and "items" in node:
        rows(schema, node["items"], f"{path}[]", False, out, depth + 1)
    for key in ("oneOf", "anyOf"):
        for index, variant in enumerate(node.get(key, [])):
            variant = deref(schema, variant)
            if variant.get("properties") or variant.get("type") == "array":
                rows(schema, variant, f"{path}（变体 {index + 1}）" if path else "", False, out, depth + 1)


def generate(schema):
    out = [HEADER.rstrip("\n"), ""]
    for name, child in schema["properties"].items():
        if name == "$schema":
            continue
        section = []
        rows(schema, child, name, False, section)
        out.append(f"## `{name}`")
        out.append("")
        out.append("| 字段 | 类型 | 默认值 | 取值范围 | 说明 |")
        out.append("|---|---|---|---|---|")
        out.extend(section)
        out.append("")
    return "\n".join(out)


def main(argv):
    write = "--write" in argv
    paths = [a for a in argv if not a.startswith("--")]
    schema = json.loads(Path(paths[0]).read_text(encoding="utf-8"))
    document = Path(paths[1])
    text = generate(schema)
    if write:
        document.write_text(text, encoding="utf-8")
        return 0
    if not document.exists() or document.read_text(encoding="utf-8") != text:
        print("docs/configuration.md is out of date; regenerate it from schema/ftun.schema.json", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
