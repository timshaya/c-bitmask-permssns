#!/usr/bin/env python3
"""Static cardinality policy check. Exit 0: pass/skip, 1: risk, 2: scan error.

Recognizes PromQL in YAML/JSON expr fields, Grafana query fields, .promql
files, Prometheus exposition, and selected C/Java/Kotlin instrumentation.
This is a heuristic policy check, not a PromQL parser or a runtime measurement.

Update RISKY_LABELS values as/if needed.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import sys

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


RISKY_LABELS = {
    "user_id", "request_id", "session_id", "trace_id", "span_id",
    "correlation_id", "transaction_id", "email", "email_address",
}
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "vendor", "build", "dist",
    "target", ".gradle", ".idea", "__pycache__",
}
CONFIG_EXTS = {".yaml", ".yml", ".json", ".rules"}
SOURCE_EXTS = {".c", ".h", ".java", ".kt", ".kts"}
RAW_EXTS = {".promql", ".prom"}
TOKEN = re.compile(
    r'''(?P<string>"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`[^`]*`)'''
    r"|(?P<comment>//[^\n]*|/\*[\s\S]*?\*/|\#[^\n]*)"
    r"|(?P<word>[a-zA-Z_][a-zA-Z0-9_:]*)"
    r"|(?P<op>=~|!~|!=|=)|(?P<punct>[^\s])"
)


def normalize(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    label: str
    context: str


def tokens(text: str):
    return [m for m in TOKEN.finditer(text) if m.lastgroup != "comment"]


def token_value(token) -> str:
    value = token.group()
    return value[1:-1] if token.lastgroup == "string" else value


def query_labels(query: str):
    """Yield (label name, offset), respecting quotes, comments and operators."""
    ts = tokens(query)
    in_selector = False
    for i, t in enumerate(ts):
        value = t.group()
        if value == "{":
            in_selector = True
        elif value == "}":
            in_selector = False
        elif in_selector and i + 1 < len(ts) and ts[i + 1].lastgroup == "op":
            if t.lastgroup in {"word", "string"}:
                yield token_value(t), t.start()
        elif value in {"by", "without", "on", "ignoring", "group_left", "group_right"}:
            if i + 1 < len(ts) and ts[i + 1].group() == "(":
                for item in ts[i + 2:]:
                    if item.group() == ")":
                        break
                    if item.lastgroup in {"word", "string"}:
                        yield token_value(item), item.start()
        elif value == "label_values" and i + 1 < len(ts) and ts[i + 1].group() == "(":
            # Grafana classic variable syntax: label_values(metric, label).
            depth, args, current = 1, [], []
            for item in ts[i + 2:]:
                if item.group() in {"(", "{"}:
                    depth += 1
                elif item.group() in {")", "}"}:
                    depth -= 1
                    if depth == 0:
                        args.append(current)
                        break
                if item.group() == "," and depth == 1:
                    args.append(current)
                    current = []
                else:
                    current.append(item)
            if args and len(args[-1]) == 1:
                item = args[-1][0]
                yield token_value(item), item.start()


def config_queries(text: str):
    """Use YAML node marks for source locations, including escaped JSON strings."""
    seen = set()

    def visit(node, monitored=False):
        # YAML aliases can form cycles; never traverse the same state twice.
        state = (id(node), monitored)
        if state in seen:
            return
        seen.add(state)
        if isinstance(node, MappingNode):
            fields = {k.value: v for k, v in node.value if isinstance(k, ScalarNode)}
            monitored = monitored or bool({"panels", "targets", "templating"} & fields.keys())
            ds = fields.get("datasource")
            if isinstance(ds, MappingNode):
                ds = next((v for k, v in ds.value if k.value == "type"), None)
            if isinstance(ds, ScalarNode):
                # Grafana supports other query languages; do not lint Loki/SQL.
                if ds.value.lower() in {"loki", "mysql", "postgres", "elasticsearch", "influxdb"}:
                    return
                monitored = monitored or ds.value.lower() == "prometheus"
            for key, value in fields.items():
                if isinstance(value, ScalarNode) and (
                    key in {"expr", "promql"} or (monitored and key == "query")
                ):
                    # A block scalar's content starts after its | or > marker.
                    base_line = value.start_mark.line + 1 + (value.style in {"|", ">"})
                    yield value.value, base_line
                else:
                    yield from visit(value, monitored)
        elif isinstance(node, SequenceNode):
            for value in node.value:
                yield from visit(value, monitored)

    for document in yaml.compose_all(text, Loader=yaml.SafeLoader):
        if document is not None:
            yield from visit(document)


def source_labels(text: str):
    """Literal label keys in common Prometheus JVM and Micrometer calls."""
    ts = tokens(text)
    for i, t in enumerate(ts):
        if t.group() not in {"labelNames", "labelKeys", "tag", "tags", "of"}:
            continue
        if t.group() == "of" and not (
            i >= 2 and ts[i - 2].group() in {"Tag", "Tags"} and ts[i - 1].group() == "."
        ):
            continue
        if i + 1 >= len(ts) or ts[i + 1].group() != "(":
            continue
        # tag/tags are also generic APIs: require an instrumentation import.
        if t.group() in {"tag", "tags", "of"} and not re.search(
            r"\b(?:io\.micrometer|io\.prometheus)\b", text
        ):
            continue
        depth, arg_index = 1, 0
        for item in ts[i + 2:]:
            if item.group() == "(":
                depth += 1
            elif item.group() == ")":
                depth -= 1
                if depth == 0:
                    break
            elif item.group() == "," and depth == 1:
                arg_index += 1
            elif depth == 1 and item.lastgroup == "string":
                all_keys = t.group() in {"labelNames", "labelKeys"}
                single_key = t.group() == "tag" or (t.group() == "of" and ts[i - 2].group() == "Tag")
                if all_keys or (single_key and arg_index == 0) or (not single_key and arg_index % 2 == 0):
                    yield token_value(item), item.start()

    # prometheus-client-c constructors reference arrays of label names.
    # Preserve offsets while removing comments so commented declarations do not count.
    clean = list(text)
    for match in TOKEN.finditer(text):
        if match.lastgroup == "comment":
            clean[match.start():match.end()] = " " * (match.end() - match.start())
    clean = "".join(clean)
    references = set()
    for i, token in enumerate(ts):
        if not re.fullmatch(r"prom_(?:counter|gauge|histogram|summary)_new", token.group()):
            continue
        if i + 1 >= len(ts) or ts[i + 1].group() != "(":
            continue
        depth, braces = 1, 0
        for item in ts[i + 2:]:
            value = item.group()
            if value == "(":
                depth += 1
            elif value == ")":
                depth -= 1
                if depth == 0:
                    break
            elif value == "{":
                braces += 1
            elif value == "}":
                braces -= 1
            elif braces and item.lastgroup == "string":
                # C compound literal: (const char *[]) {"method", "user_id"}
                yield token_value(item), item.start()
            elif item.lastgroup == "word":
                references.add(value)
    for name in references:
        for declaration in re.finditer(r"\b" + re.escape(name) + r"\s*\[[^]]*\]\s*=\s*\{([^}]*)\}", clean):
            for item in tokens(declaration.group(1)):
                if item.lastgroup == "string":
                    yield token_value(item), declaration.start(1) + item.start()


def scan_repository(root: Path, risky_labels=None, exclude=()):
    denied = {normalize(label) for label in (risky_labels or RISKY_LABELS)}
    findings, errors, monitored_files = set(), [], set()
    for directory, dirs, files in os.walk(root, onerror=lambda error: errors.append(str(error))):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and d not in exclude
                         and not (Path(directory) / d).is_symlink())
        for name in sorted(files):
            path = Path(directory) / name
            if path.is_symlink() or path.suffix not in CONFIG_EXTS | SOURCE_EXTS | RAW_EXTS:
                continue
            relative = path.relative_to(root).as_posix()
            try:
                text = path.read_text(encoding="utf-8")
                labels = []
                if path.suffix in CONFIG_EXTS:
                    if path.suffix == ".json":
                        json.loads(text)  # Require valid JSON, not merely valid YAML.
                    for query, line in config_queries(text):
                        monitored_files.add(relative)
                        for label, offset in query_labels(query):
                            # Quoted JSON/YAML strings have escaped newlines on one
                            # source line. Use the field line for these findings.
                            labels.append((label, line, "monitoring query"))
                elif path.suffix in RAW_EXTS:
                    if path.suffix == ".promql" or list(query_labels(text)):
                        monitored_files.add(relative)
                    labels = [(label, text.count("\n", 0, offset) + 1, "monitoring query/sample")
                              for label, offset in query_labels(text)]
                else:
                    declarations = list(source_labels(text))
                    if declarations:
                        monitored_files.add(relative)
                    labels = [(label, text.count("\n", 0, offset) + 1, "metric label declaration")
                              for label, offset in declarations]
                for label, line, context in labels:
                    if normalize(label) in denied:
                        findings.add(Finding(relative, line, label, context))
            except (OSError, UnicodeError, ValueError, yaml.YAMLError) as error:
                errors.append(f"{relative}: {error}")
    return sorted(findings), errors, len(monitored_files)


def annotation_escape(value: str, property_value=False) -> str:
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    return value.replace(":", "%3A").replace(",", "%2C") if property_value else value


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--deny-label", action="append", default=[], help="Additional risky label name; repeatable")
    parser.add_argument("--exclude-dir", action="append", default=[], help="Additional directory basename to skip")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"ERROR: repository directory does not exist: {root}", file=sys.stderr)
        return 2
    findings, errors, monitored = scan_repository(root, RISKY_LABELS | set(args.deny_label), args.exclude_dir)
    for finding in findings:
        message = (
            f"Potential high cardinality: label '{finding.label}' in {finding.context}. "
            "Per-user/request/session identifiers can create unbounded time series. "
            "Remove this metric label; use bounded dimensions such as method, status, "
            "or route template. Keep individual IDs in logs or traces. "
            "If found in a query, inspect the metric's instrumentation."
        )
        print(f"{finding.path}:{finding.line}: ERROR: {message}")
        if os.environ.get("GITHUB_ACTIONS") == "true":
            # GitHub annotation paths are relative to GITHUB_WORKSPACE, not the scan root.
            workspace = Path(os.environ.get("GITHUB_WORKSPACE", str(root))).resolve()
            file = os.path.relpath(root / finding.path, workspace)
            print(f"::error file={annotation_escape(file, True)},line={finding.line},title=High cardinality::{annotation_escape(message)}")
    for error in errors:
        print(f"ERROR: unable to complete cardinality scan: {error}", file=sys.stderr)
    if errors:
        return 2
    if findings:
        print(f"FAIL: {len(findings)} risky label reference(s) in {monitored} monitoring file(s).")
        return 1
    if monitored:
        print(f"PASS: no prohibited label names in {monitored} monitoring file(s).")
    else:
        print("SKIP: no supported monitoring queries or metric label declarations found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
