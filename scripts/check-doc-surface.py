#!/usr/bin/env python3
"""Require examples for the actual CLI, routed API, WIT and error catalog."""
import argparse
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit


class InvalidSurface(ValueError):
    pass


def sections(text, level=2):
    pattern = re.compile(r"^" + "#" * level + r" ([^\n]+)\n?$")
    headings = []
    offset = 0
    fence = None
    for line in text.splitlines(keepends=True):
        marker = re.match(r"^ {0,3}(`{3,}|~{3,})([^\n]*)", line)
        if fence is not None:
            if marker and marker.group(1)[0] == fence[0] and len(marker.group(1)) >= len(fence) and not marker.group(2).strip():
                fence = None
        elif marker:
            fence = marker.group(1)
        else:
            heading = pattern.match(line)
            if heading:
                headings.append((heading.group(1), offset, offset + len(line)))
        offset += len(line)
    if fence is not None:
        raise InvalidSurface("unterminated fenced documentation example")
    result = {}
    for index, (title, start, end) in enumerate(headings):
        if title in result:
            raise InvalidSurface(f"duplicate documentation section: {title}")
        result[title] = text[end:headings[index + 1][1] if index + 1 < len(headings) else len(text)]
    return result


def fences(text):
    return [(match.group(1).strip(), match.group(2))
            for match in re.finditer(r"^```([^\n]*)\n(.*?)^```\s*$", text, re.MULTILINE | re.DOTALL)]


def help_output(binary, arguments):
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run([str(binary), *arguments, "--help"], stdout=output, stderr=errors, timeout=5)
        output.seek(0)
        help_bytes = output.read(131073)
        errors.seek(0)
        if result.returncode or len(help_bytes) > 131072 or errors.read(1):
            raise InvalidSurface(f"cannot parse actual CLI {' '.join(arguments)} --help")
        return help_bytes.decode("utf-8")


def command_example(body, command, binary=None):
    for language, example in fences(body):
        if language not in ("", "sh", "bash", "shell", "text", "console"):
            continue
        for line in example.replace("\\\n", " ").splitlines():
            try:
                words = shlex.split(line.lstrip("$ "))
            except ValueError:
                continue
            if "kronik" not in words:
                continue
            words = words[words.index("kronik") + 1:]
            arguments = words.copy()
            for index, word in enumerate(arguments):
                if word in ("|", "&&", ";", ">", "2>"):
                    arguments = arguments[:index]
                    break
            while words and words[0].startswith("--"):
                flag = words.pop(0)
                if flag in ("--socket", "--url", "--token") and words:
                    words.pop(0)
                elif flag != "--json":
                    break
            if words[:len(command)] == command:
                if binary is not None:
                    try:
                        help_output(binary, arguments)
                    except InvalidSurface:
                        continue
                return True
    return False


def cli_leaves(binary, root):
    hidden = re.findall(r"#\[command\([^)]*\bhide\s*=\s*true[^)]*\)\]\s*([A-Z][A-Za-z0-9]*)",
                        (root / "crates/kronik/src/main.rs").read_text())
    queue = [[], *[[re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()] for name in hidden]]
    leaves = []
    while queue:
        prefix = queue.pop()
        if len(prefix) > 8 or len(queue) + len(leaves) > 256:
            raise InvalidSurface("CLI tree exceeds its finite inventory bounds")
        help_text = help_output(binary, prefix)
        commands = []
        in_commands = False
        for line in help_text.splitlines():
            if line == "Commands:":
                in_commands = True
            elif in_commands and line and not line.startswith(" "):
                in_commands = False
            elif in_commands:
                match = re.match(r"^  ([a-z][a-z0-9-]*)\s+", line)
                if match and match.group(1) != "help":
                    commands.append(match.group(1))
        if commands:
            queue.extend([*prefix, command] for command in commands)
        elif prefix:
            leaves.append(prefix)
    if not leaves:
        raise InvalidSurface("actual CLI yielded no commands")
    return sorted(leaves)


def wit_functions(text):
    text = re.sub(r"//[^\n]*", "", text)
    result = []
    for interface in re.finditer(r"\binterface\s+([a-z][a-z0-9-]*)\s*\{", text):
        depth = 1
        end = interface.end()
        while depth and end < len(text):
            depth += (text[end] == "{") - (text[end] == "}")
            end += 1
        if depth:
            raise InvalidSurface("unterminated WIT interface")
        for function in re.finditer(r"\b([a-z][a-z0-9-]*)\s*:\s*func\s*\(", text[interface.end():end - 1]):
            result.append((interface.group(1), function.group(1)))
    if not result or len(result) > 512 or len(result) != len(set(result)):
        raise InvalidSurface("invalid or empty WIT function inventory")
    return sorted(result)


def rust_views(text):
    """Keep literal code plus delimiter layout, masking comments and literals."""
    token = re.compile(r'//[^\n]*|/\*|r(?P<hashes>#{0,32})".*?"(?P=hashes)|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])\'', re.DOTALL)
    code, layout = [], []
    position = 0
    while match := token.search(text, position):
        start, end = match.span()
        comment = match.group().startswith(("//", "/*"))
        if match.group() == "/*":
            depth = 1
            for marker in re.finditer(r"/\*|\*/", text[end:]):
                depth += 1 if marker.group() == "/*" else -1
                if depth == 0:
                    end += marker.end()
                    break
            else:
                raise InvalidSurface("unterminated Rust block comment")
        code.extend((text[position:start], " " * (end - start) if comment else text[start:end]))
        layout.extend((text[position:start], " " * (end - start)))
        position = end
    code.append(text[position:])
    layout.append(text[position:])
    return "".join(code), "".join(layout)


def delimited_end(layout, start):
    opener = layout[start]
    closer = {"{": "}", "(": ")", "[": "]"}[opener]
    depth = 1
    for index in range(start + 1, len(layout)):
        depth += (layout[index] == opener) - (layout[index] == closer)
        if depth == 0:
            return index
    raise InvalidSurface("unterminated Rust API dispatch delimiter")


def split_rust(text, layout, separator=","):
    stack, start, parts = [], 0, []
    for index, character in enumerate(layout):
        if character in "({[":
            stack.append(character)
        elif character in ")}]":
            if not stack or stack.pop() != {")": "(", "}": "{", "]": "["}[character]:
                raise InvalidSurface("unbalanced Rust API dispatch")
        elif character == separator and not stack:
            parts.append(text[start:index].strip())
            start = index + 1
    if stack:
        raise InvalidSurface("unbalanced Rust API dispatch")
    parts.append(text[start:].strip())
    return [part for part in parts if part]


def match_patterns(text, layout):
    """Rust block match arms may omit the comma after their closing brace."""
    stack, start = [], 0
    index = 0
    while index < len(layout):
        character = layout[index]
        if character in "({[":
            stack.append(character)
        elif character in ")}]":
            if not stack or stack.pop() != {")": "(", "}": "{", "]": "["}[character]:
                raise InvalidSurface("unbalanced Rust API match arm")
            if character == "}" and not stack:
                start = index + 1
        elif not stack:
            if character == ",":
                start = index + 1
            elif layout[index:index + 2] == "=>":
                yield text[start:index].strip()
                index += 1
        index += 1
    if stack:
        raise InvalidSurface("unbalanced Rust API match arm")


def routed_api(text):
    """Read the existing literal method/segment dispatch convention, not its docs."""
    code, layout = rust_views(text)
    operations = set()
    function = re.compile(r"\bfn\s+route(?:_[A-Za-z0-9_]+)?\s*\(")
    dispatch = re.compile(r"\bmatch\s*\(\s*req\.method\.as_str\(\)\s*,\s*segs(?:\.as_slice\(\))?\s*\)\s*\{")
    pattern = re.compile(r'\(\s*("[A-Z]+"(?:\s*\|\s*"[A-Z]+")*)\s*,\s*\[(.*)\]\s*\)', re.DOTALL)
    for route in function.finditer(layout):
        start = layout.find("{", route.end())
        if start < 0:
            raise InvalidSurface("API route function has no body")
        end = delimited_end(layout, start)
        matches = list(dispatch.finditer(layout, start, end))
        if not matches:
            raise InvalidSurface("unsupported API route dispatch: " + layout[route.start():route.end()].strip())
        for match in matches:
            body_end = delimited_end(layout, match.end() - 1)
            for arm_pattern in match_patterns(code[match.end():body_end], layout[match.end():body_end]):
                if arm_pattern == "_":
                    continue
                _, arm_layout = rust_views(arm_pattern)
                for alternative in split_rust(arm_pattern, arm_layout, "|"):
                    parsed = pattern.fullmatch(alternative)
                    if not parsed:
                        raise InvalidSurface("unsupported API method/path pattern: " + alternative)
                    segments = []
                    segment_code, segment_layout = rust_views(parsed.group(2))
                    for segment in split_rust(segment_code, segment_layout):
                        if re.fullmatch(r'"(?:\\.|[^"\\])*"', segment):
                            segments.append(json.loads(segment))
                        elif re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", segment):
                            segments.append("{}")
                        else:
                            raise InvalidSurface("unsupported API path segment: " + segment)
                    for method in re.findall(r'"([A-Z]+)"', parsed.group(1)):
                        operation = method + " /" + "/".join(segments)
                        if operation in operations:
                            raise InvalidSurface("duplicate actual API route: " + operation)
                        operations.add(operation)
                        if len(operations) > 2048:
                            raise InvalidSurface("API route inventory exceeds its finite bound")
    return operations


def event_stream_api(server, handler):
    """Inventory the server's real pre-body stream dispatch and GET rejection."""
    code, layout = rust_views(server)
    calls = {match.start() for match in re.finditer(r"\bcrate::event_stream::serve\s*\(", layout)}
    if not calls:
        return set()
    dispatch = re.compile(r'if\s+matches!\(\s*req\.path\.as_str\(\)\s*,\s*("(?:\\.|[^"\\])*"(?:\s*\|\s*"(?:\\.|[^"\\])*")*)\s*\)\s*\{')
    covered, paths = set(), set()
    for match in dispatch.finditer(code):
        if layout[match.start():match.start() + 2] != "if":
            continue
        end = delimited_end(layout, match.end() - 1)
        reached = {position for position in calls if match.end() <= position < end}
        if reached:
            covered.update(reached)
            paths.update(json.loads(value) for value in re.findall(r'"(?:\\.|[^"\\])*"', match.group(1)))
    if covered != calls or not paths:
        raise InvalidSurface("unsupported server event-stream dispatch")
    handler_code, handler_layout = rust_views(handler)
    guard = re.search(r'\bif\s+request\.method\s*!=\s*"GET"', handler_code)
    if guard is None or handler_layout[guard.start():guard.start() + 2] != "if":
        raise InvalidSurface("event-stream handler has no explicit GET rejection")
    start = handler_layout.find("{", guard.end())
    if start < 0:
        raise InvalidSurface("event-stream method rejection has no body")
    condition = handler_code[guard.end():start].strip()
    body = handler_code[start + 1:delimited_end(handler_layout, start)].strip()
    if (condition and not condition.startswith("||")) or not re.match(r"return\s+Err\s*\(", body):
        raise InvalidSurface("unsupported event-stream method rejection")
    return {"GET " + path for path in paths}


def actual_api(root):
    source_root = root / "crates/kronik-api/src"
    operations = set()
    server, handler = "", ""
    for source in sorted(source_root.rglob("*.rs")):
        text = source.read_text()
        operations.update(routed_api(text))
        if source == source_root / "server.rs":
            server = text
        elif source == source_root / "event_stream.rs":
            handler = text
    operations.update(event_stream_api(server, handler))
    return operations


def normalized_operation(operation):
    return re.sub(r"\{[^{}]*\}", "{}", operation)


def api_example(body, method, path):
    method = method.upper()
    path_pattern = "".join(r"[^\s/?]+" if part.startswith("{") else re.escape(part)
                           for part in re.split(r"(\{[^}]+\})", path))
    request = re.compile(r"^\s*" + re.escape(method) + " " + path_pattern +
                         r"(?:\?[^\s]*)?\s+HTTP/[0-9.]+\s*$", re.MULTILINE)
    for language, example in fences(body):
        if language in ("http", "text") and request.search(example):
            return True
        if language not in ("sh", "bash", "shell", "console", "text"):
            continue
        for line in example.replace("\\\n", " ").splitlines():
            try:
                words = shlex.split(line.lstrip("$ "))
            except ValueError:
                continue
            for index, word in enumerate(words):
                if word != "curl":
                    continue
                args = words[index + 1:]
                end = next((offset for offset, value in enumerate(args) if value in ("|", "&&", ";")), len(args))
                args = args[:end]
                verb = next((args[offset + 1] for offset, value in enumerate(args[:-1]) if value in ("--request", "-X")), None)
                url = next((args[offset + 1] for offset, value in enumerate(args[:-1]) if value == "--url"), None)
                if verb != method or url is None:
                    continue
                try:
                    parsed = urlsplit(url)
                except ValueError:
                    continue
                if parsed.scheme in ("http", "https") and re.fullmatch(path_pattern, parsed.path):
                    return True
    return False


def check(root, binary):
    missing = []
    cli_doc = sections((root / "docs/reference/cli.md").read_text())
    cli = cli_leaves(binary, root)
    examples = set()
    for command in cli:
        name = " ".join(command)
        body = cli_doc.get("kronik " + name, "")
        if not body or not command_example(body, command, binary):
            missing.append("CLI example: " + name)
        else:
            examples.add(name)
    # The generated JSON reference maps real CLI consumers to their API schema.
    # Endpoints without a CLI consumer require their own explicit HTTP example.
    json_doc = (root / "docs/reference/json.md").read_text()
    additional = (root / "docs/reference/api-examples.md").read_text()
    api = json.loads((root / "docs/reference/openapi.json").read_text())
    operations = []
    for path, item in api["paths"].items():
        for method, operation in item.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                continue
            name = method.upper() + " " + path
            operations.append(name)
            mapped = False
            for line in json_doc.splitlines():
                if f"`{name}`" in line:
                    command = re.search(r"\| `kronik ([^`]+)`", line)
                    if command and command.group(1) in examples:
                        mapped = True
            explicit = sections(additional).get(name, "")
            explicit_example = api_example(explicit, method, path)
            if not operation.get("summary") or not operation.get("responses") or not (mapped or explicit_example):
                missing.append("API example/schema: " + name)
    if not operations:
        raise InvalidSurface("OpenAPI declared no operations")
    actual_operations = actual_api(root)
    if not actual_operations:
        raise InvalidSurface("actual API dispatch yielded no operations")
    declared = {normalized_operation(operation) for operation in operations}
    if len(declared) != len(operations):
        raise InvalidSurface("OpenAPI declares ambiguous duplicate method/path shapes")
    missing.extend("API route missing OpenAPI: " + operation for operation in sorted(actual_operations - declared))
    missing.extend("OpenAPI has no API route: " + operation for operation in sorted(declared - actual_operations))
    wit_doc = sections((root / "docs/reference/wit.md").read_text())
    wit_examples = sections((root / "docs/reference/wit-examples.md").read_text())
    wit = wit_functions((root / "wit/kronik-actor.wit").read_text())
    for interface, function in wit:
        body = wit_doc.get(interface, "") + "\n" + wit_examples.get(interface, "")
        if interface == "handler":
            token = r"\bfn\s+" + re.escape(function.replace("-", "_")) + r"\s*\("
        else:
            token = re.escape(interface.replace("-", "_")) + r"(?:::|\.)" + re.escape(function.replace("-", "_")) + r"\s*\("
        if not any(language != "wit" and re.search(token, example) for language, example in fences(body)):
            missing.append("WIT usage example: " + interface + "." + function)
    error_source = (root / "crates/kronik-core/src/error.rs").read_text()
    errors = re.findall(r'^\s+[A-Za-z][A-Za-z0-9]*\s*=\s*"([A-Z][A-Z0-9_]*)",\s*\d+,', error_source, re.MULTILINE)
    if not errors or len(errors) != len(set(errors)):
        raise InvalidSurface("invalid or empty authoritative error catalog")
    error_docs = sections((root / "docs/errors.md").read_text())
    error_examples = sections((root / "docs/reference/error-examples.md").read_text())
    for error in errors:
        body = error_docs.get(error, "")
        example_body = error_examples.get(error, "")
        action = any(command != ["explain"] and command_example(example_body, command, binary)
                     for command in cli)
        action = action or any(re.search(r"\bcurl |^(?:GET|POST|PUT|DELETE|PATCH) /", example, re.MULTILINE)
                               for language, example in fences(example_body)
                               if language in ("sh", "bash", "text", "http", "console"))
        if not body or not example_body or not action:
            missing.append("Error cause/remediation example: " + error)
    return {"format": "kronik.documentation-surface/v1", "cli_commands": len(cli),
            "api_operations": len(operations), "routed_api_operations": len(actual_operations),
            "wit_functions": len(wit), "error_codes": len(errors),
            "missing": missing, "passed": not missing}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = check(args.root.resolve(strict=True), args.binary.resolve(strict=True))
    print(json.dumps(result, allow_nan=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"documentation surface: {error}", file=sys.stderr)
        sys.exit(2)
