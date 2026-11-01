#!/usr/bin/env python3
"""Conservative backward-compatibility checks for the published JSON contract subset.

Unknown changed validation keywords fail closed; this is not a JSON Schema validator.
The real binary consumers and generated-schema consistency tests remain necessary.
"""
import json
import re


class BreakingContract(ValueError):
    pass


ANNOTATIONS = {"title", "description", "examples", "$comment", "deprecated"}
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
WIT_TOKEN = re.compile(r"(?:%?[a-z][a-z0-9-]*|[0-9]+|->|[^\s])")


def same_json_value(left, right):
    """JSON booleans are not numbers; JSON numeric 1 and 1.0 are equal."""
    if isinstance(left, bool) or isinstance(right, bool):
        return type(left) is type(right) and left == right
    if type(left) in (int, float) and type(right) in (int, float):
        return left == right
    if type(left) is not type(right):
        return False
    if isinstance(left, list):
        return len(left) == len(right) and all(same_json_value(a, b) for a, b in zip(left, right))
    if isinstance(left, dict):
        return left.keys() == right.keys() and all(same_json_value(value, right[key]) for key, value in left.items())
    return left == right


def resolve(schema, document, reference_defaults=None):
    seen = set()
    while isinstance(schema, dict) and "$ref" in schema:
        if reference_defaults is not None and "default" in schema:
            reference_defaults.append(schema["default"])
        reference = schema["$ref"]
        if not isinstance(reference, str) or not reference.startswith("#/") or reference in seen:
            raise BreakingContract("unsupported, cyclic alias or external schema reference")
        seen.add(reference)
        target = document
        try:
            for key in reference[2:].split("/"):
                target = target[key.replace("~1", "/").replace("~0", "~")]
        except (KeyError, TypeError) as error:
            raise BreakingContract(f"dangling schema reference: {reference}") from error
        siblings = {key: value for key, value in schema.items() if key not in {"$ref", "default"} and key not in ANNOTATIONS}
        if siblings:
            raise BreakingContract("schema reference with validation siblings needs explicit compatibility review")
        schema = target
    return schema


def schema_compatible(old, new, old_document, new_document, direction, path="schema", seen=None):
    """Requests keep accepting old values; responses keep satisfying old consumers."""
    if direction not in ("request", "response"):
        raise ValueError("unknown compatibility direction")
    old_defaults, new_defaults = [], []
    old, new = resolve(old, old_document, old_defaults), resolve(new, new_document, new_defaults)
    if not same_json_value(old_defaults, new_defaults):
        raise BreakingContract(f"{path}: referenced field default changed")
    if type(old) is bool and type(new) is bool and old == new:
        return
    if old is False or new is True:
        if direction == "request":
            return
    if new is False or old is True:
        if direction == "response":
            return
    if isinstance(old, bool) or isinstance(new, bool) or not isinstance(old, dict) or not isinstance(new, dict):
        raise BreakingContract(f"{path}: schema language changed")
    seen = set() if seen is None else seen
    pair = (id(old), id(new), direction)
    if pair in seen:
        return
    seen = seen | {pair}
    def compare(left, right, where):
        schema_compatible(left, right, old_document, new_document, direction, where, seen)
    def fail(reason):
        raise BreakingContract(f"{path}: {reason}")
    def values(value):
        if value is None:
            return None
        result = set(value if isinstance(value, list) else [value])
        if "number" in result:
            result.remove("number")
            result.update(("integer", "fractional"))
        return result
    old_types, new_types = values(old.get("type")), values(new.get("type"))
    narrow, wide = (old_types, new_types) if direction == "request" else (new_types, old_types)
    if wide is not None and (narrow is None or not narrow <= wide):
        fail("accepted/emitted types or nullability are incompatible")
    def enum_values(schema):
        choices = schema.get("enum")
        if "const" not in schema:
            return choices
        value = schema["const"]
        return [value] if choices is None or any(same_json_value(value, choice) for choice in choices) else []
    old_enum, new_enum = enum_values(old), enum_values(new)
    narrow, wide = (old_enum, new_enum) if direction == "request" else (new_enum, old_enum)
    if wide is not None and (narrow is None or any(not any(same_json_value(item, choice) for choice in wide) for item in narrow)):
        fail("enum or constant values are incompatible")
    old_required, new_required = set(old.get("required", [])), set(new.get("required", []))
    if (direction == "request" and not new_required <= old_required) or (direction == "response" and not old_required <= new_required):
        fail("required fields changed incompatibly")
    old_properties, new_properties = old.get("properties", {}), new.get("properties", {})
    for name, child in old_properties.items():
        if name not in new_properties:
            fail(f"field removed: {name}")
        compare(child, new_properties[name], path + "/" + name)
    for name in new_properties.keys() - old_properties.keys():
        compare(old.get("additionalProperties", True), new_properties[name], path + "/" + name)
    compare(old.get("additionalProperties", True), new.get("additionalProperties", True), path + "/additionalProperties")
    if "items" in old or "items" in new:
        compare(old.get("items", True), new.get("items", True), path + "/items")
    for keyword in ("anyOf", "oneOf"):
        if keyword not in old and keyword not in new:
            continue
        if keyword not in old or keyword not in new:
            fail(f"{keyword} composition changed")
        left, right = old[keyword], new[keyword]
        if keyword == "oneOf" and len(left) != len(right):
            fail("oneOf exclusivity changed")
        sources, targets = (left, right) if direction == "request" else (right, left)
        for index, source in enumerate(sources):
            matched = False
            for target in targets:
                before, after = (source, target) if direction == "request" else (target, source)
                try:
                    compare(before, after, f"{path}/{keyword}/{index}")
                    if keyword == "oneOf":
                        schema_compatible(before, after, old_document, new_document,
                                          "response" if direction == "request" else "request", seen=seen)
                except BreakingContract:
                    continue
                matched = True
                break
            if not matched:
                fail(f"{keyword} variant removed or changed")
    for keyword, lower in (("minimum", True), ("exclusiveMinimum", True), ("minLength", True),
                           ("minItems", True), ("minProperties", True), ("maximum", False),
                           ("exclusiveMaximum", False), ("maxLength", False), ("maxItems", False), ("maxProperties", False)):
        before, after = old.get(keyword), new.get(keyword)
        narrow, wide = (before, after) if direction == "request" else (after, before)
        if wide is not None and (narrow is None or (narrow < wide if lower else narrow > wide)):
            fail(f"{keyword} restricts old requests or widens responses")
    handled = {"type", "enum", "const", "required", "properties", "additionalProperties", "items", "anyOf", "oneOf",
               "minimum", "exclusiveMinimum", "minLength", "minItems", "minProperties", "maximum", "exclusiveMaximum",
               "maxLength", "maxItems", "maxProperties", "$defs", "definitions"} | ANNOTATIONS
    for keyword in (old.keys() | new.keys()) - handled:
        if (keyword in old) != (keyword in new) or not same_json_value(old.get(keyword), new.get(keyword)):
            fail(f"changed {keyword} needs explicit compatibility proof")


def attributes_compatible(old, new, handled, path):
    annotations = ANNOTATIONS | {"summary", "example", "externalDocs", "tags"}
    for key in (old.keys() | new.keys()) - set(handled) - annotations:
        if (key in old) != (key in new) or not same_json_value(old.get(key), new.get(key)):
            raise BreakingContract(f"{path}: changed {key} needs explicit compatibility proof")


def content_compatible(old, new, old_document, new_document, direction, path):
    if set(old) - set(new):
        raise BreakingContract(f"{path}: published media type removed")
    for media_type, value in old.items():
        attributes_compatible(value, new[media_type], {"schema"}, path + "/" + media_type)
        schema_compatible(value.get("schema", True), new[media_type].get("schema", True),
                          old_document, new_document, direction, path + "/" + media_type)
        if direction == "response" and new[media_type].get("schema") is False and value.get("schema") is not False:
            raise BreakingContract(f"{path}: response schema became impossible")
    if direction == "response" and set(new) - set(old):
        raise BreakingContract(f"{path}: new response media type needs explicit client compatibility")


def parameters(item, operation, document):
    result = {}
    for level in (item, operation):
        for value in level.get("parameters", []):
            value = resolve(value, document)
            result[(value["in"], value["name"])] = value
    return result


def api_compatible(old, new):
    if old.get("openapi") != new.get("openapi") or old.get("security") != new.get("security"):
        raise BreakingContract("API schema dialect or global authorization changed")
    attributes_compatible(old, new, {"openapi", "security", "info", "paths", "components"}, "API")
    for name, scheme in old.get("components", {}).get("securitySchemes", {}).items():
        replacement = new.get("components", {}).get("securitySchemes", {}).get(name)
        if not isinstance(replacement, dict):
            raise BreakingContract("published API authorization scheme removed")
        attributes_compatible(scheme, replacement, set(), f"API authorization scheme {name}")
    operations = 0
    for path, unresolved_item in old["paths"].items():
        item = resolve(unresolved_item, old)
        current_item = resolve(new.get("paths", {}).get(path, {}), new)
        attributes_compatible(item, current_item, HTTP_METHODS | {"parameters"}, path)
        for method, operation in item.items():
            if method not in HTTP_METHODS:
                continue
            current = current_item.get(method)
            if not isinstance(current, dict):
                raise BreakingContract(f"API operation removed: {method.upper()} {path}")
            where = method.upper() + " " + path
            attributes_compatible(operation, current, {"operationId", "security", "x-kronik-scope", "parameters", "requestBody", "responses"}, where)
            for key in ("operationId", "security", "x-kronik-scope"):
                if operation.get(key) != current.get(key):
                    raise BreakingContract(f"{where}: {key} changed")
            before = parameters(item, operation, old)
            after = parameters(current_item, current, new)
            if before.keys() - after.keys() or any(p.get("required", False) for key, p in after.items() if key not in before):
                raise BreakingContract(f"{where}: parameter removed or new required parameter")
            for key, parameter in before.items():
                if not parameter.get("required", False) and after[key].get("required", False):
                    raise BreakingContract(f"{where}: optional parameter became required")
                attributes_compatible(parameter, after[key], {"in", "name", "required", "schema", "content", "style", "explode", "allowReserved", "allowEmptyValue"}, str(key))
                for serialization_key, default in (("style", "form" if key[0] in ("query", "cookie") else "simple"),
                                                   ("explode", key[0] in ("query", "cookie")), ("allowReserved", False),
                                                   ("allowEmptyValue", False)):
                    if parameter.get(serialization_key, default) != after[key].get(serialization_key, default):
                        raise BreakingContract(f"{where}: parameter serialization changed")
                schema_compatible(parameter.get("schema", True), after[key].get("schema", True), old, new, "request", str(key))
                content_compatible(parameter.get("content", {}), after[key].get("content", {}), old, new, "request", str(key))
            request = resolve(operation.get("requestBody", {}), old)
            current_request = resolve(current.get("requestBody", {}), new)
            if not request.get("required", False) and current_request.get("required", False):
                raise BreakingContract(f"{where}: body became required")
            attributes_compatible(request, current_request, {"required", "content"}, where + "/request")
            content_compatible(request.get("content", {}), current_request.get("content", {}), old, new, "request", where)
            for status, response in operation.get("responses", {}).items():
                replacement = current.get("responses", {}).get(status)
                if replacement is None:
                    raise BreakingContract(f"{where}: response status removed: {status}")
                response, replacement = resolve(response, old), resolve(replacement, new)
                attributes_compatible(response, replacement, {"headers", "content"}, where + "/" + status)
                for header, value in response.get("headers", {}).items():
                    headers = {name.lower(): item for name, item in replacement.get("headers", {}).items()}
                    if header.lower() not in headers:
                        raise BreakingContract(f"{where}: response header removed")
                    before_header, after_header = resolve(value, old), resolve(headers[header.lower()], new)
                    if before_header.get("required", False) and not after_header.get("required", False):
                        raise BreakingContract(f"{where}: required response header became optional")
                    attributes_compatible(before_header, after_header, {"schema", "content", "required"}, header)
                    content_compatible(before_header.get("content", {}), after_header.get("content", {}), old, new, "response", header)
                    schema_compatible(before_header.get("schema", True), after_header.get("schema", True), old, new, "response", header)
                content_compatible(response.get("content", {}), replacement.get("content", {}), old, new, "response", where + "/" + status)
            for status, response in current.get("responses", {}).items():
                if status not in operation.get("responses", {}):
                    fallback = operation.get("responses", {}).get("default")
                    if fallback is None:
                        raise BreakingContract(f"{where}: new status lacks an old response contract")
                    fallback, response = resolve(fallback, old), resolve(response, new)
                    content_compatible(fallback.get("content", {}), response.get("content", {}), old, new, "response", where + "/" + status)
            operations += 1
    return operations


def cli_contracts(text):
    schemas = {}
    anchors = {}
    for name, payload in re.findall(r"^### ([^\n]+)\n+```json\n(.*?)\n```", text, re.MULTILINE | re.DOTALL):
        schemas[name] = json.loads(payload)
        anchors[re.sub(r"[^a-z0-9_-]", "", name.lower().replace(" ", "-"))] = name
    commands = {}
    for command, output in re.findall(r"^\| `kronik ([^`]+)` \| (.*?) \|$", text, re.MULTILINE):
        references = re.findall(r"\[[^\]]+\]\(#([^\)]+)\)", output)
        try:
            commands[command] = [schemas[anchors[reference]] for reference in references]
        except KeyError as error:
            raise BreakingContract("dangling CLI output schema reference") from error
    if not commands or "Error" not in schemas:
        raise BreakingContract("missing generated CLI command/error schema inventory")
    return commands, {"components": {"schemas": schemas}}


def cli_compatible(old_text, new_text):
    old, old_document = cli_contracts(old_text)
    new, new_document = cli_contracts(new_text)
    for command, schemas in old.items():
        if command not in new or bool(schemas) != bool(new[command]):
            raise BreakingContract(f"CLI command or JSON availability changed: {command}")
        for schema in schemas:
            if not any_schema(schema, new[command], old_document, new_document):
                raise BreakingContract(f"CLI output changed: {command}")
        for schema in new[command]:
            matched = False
            for previous in schemas:
                try:
                    schema_compatible(previous, schema, old_document, new_document, "response")
                except BreakingContract:
                    continue
                matched = True
                break
            if not matched:
                raise BreakingContract(f"CLI introduced an incompatible output variant: {command}")
    schema_compatible(old_document["components"]["schemas"]["Error"], new_document["components"]["schemas"]["Error"],
                      old_document, new_document, "response", "CLI error")
    return len(old)


def any_schema(old, candidates, old_document, new_document):
    for candidate in candidates:
        try:
            schema_compatible(old, candidate, old_document, new_document, "response")
        except BreakingContract:
            continue
        return True
    return False


def wit_package(text):
    tokens = wit_tokens(text)
    if not tokens or tokens[0] != "package" or ";" not in tokens:
        raise BreakingContract("missing actual actor WIT package/version")
    identity = "".join(tokens[1:tokens.index(";")])
    if not re.fullmatch(r"kronik:actor@[0-9]+\.[0-9]+\.[0-9]+", identity):
        raise BreakingContract("missing actual actor WIT package/version")
    return identity


def deployment_result(status, value):
    if not isinstance(value, dict) or status not in (0, 1):
        raise BreakingContract("component deployment did not return a public success/error JSON")
    if (status == 0) == ("error" in value):
        raise BreakingContract("component deployment JSON and actual exit status disagree")


def migration_rejection(value, old_package, supported_package):
    """A generic link failure or a script-added hint is never a successful migration path."""
    error = value.get("error") if isinstance(value, dict) else None
    namespace, _, version = old_package.rpartition("@")
    old_identity = re.compile(re.escape(namespace) + r"(?:/[a-z][a-z0-9-]*)?@" + re.escape(version) + r"\b")
    return (old_package != supported_package and isinstance(error, dict) and error.get("code") == "IMPORT_NOT_ALLOWED"
            and isinstance(error.get("message"), str) and old_identity.search(error["message"]) is not None
            and isinstance(error.get("hint"), str) and supported_package in error["hint"]
            and "kronik build" in error["hint"])


def policy_result_compatible(expected, actual):
    if (not isinstance(actual, dict) or not {"outcome", "fired", "errors"} <= actual.keys()
            or not isinstance(actual["fired"], list) or not isinstance(actual["errors"], list)):
        raise BreakingContract("public policy result lost required typed fields")
    if (any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
            or not isinstance(item.get("action"), str) for item in actual["fired"])
            or any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
                   or not isinstance(item.get("message"), str) for item in actual["errors"])):
        raise BreakingContract("public policy rules/errors lost their typed fields")
    fired = [{"name": item["name"], "action": item["action"]} for item in actual["fired"]]
    errors = [item["name"] for item in actual["errors"]]
    if actual["outcome"] != expected["outcome"] or fired != expected["fired"] or errors != expected["errors"]:
        raise BreakingContract(f"public policy semantics changed: {expected['id']}")


def wit_tokens(text):
    tokens = []
    offset = 0
    while offset < len(text):
        if text.startswith("//", offset):
            end = text.find("\n", offset)
            offset = len(text) if end == -1 else end
        elif text.startswith("/*", offset):
            depth = 1
            offset += 2
            while offset < len(text) and depth:
                if text.startswith("/*", offset):
                    depth += 1
                    offset += 2
                elif text.startswith("*/", offset):
                    depth -= 1
                    offset += 2
                else:
                    offset += 1
            if depth:
                raise BreakingContract("unterminated WIT comment")
        elif text[offset].isspace():
            offset += 1
        else:
            token = WIT_TOKEN.match(text, offset)
            tokens.append(token.group())
            offset = token.end()
    return tokens


def wit_compatible(old, new):
    if wit_package(old) != wit_package(new) or wit_tokens(old) != wit_tokens(new):
        raise BreakingContract("frozen WIT ABI changed; use a new version and a real adapter/migration path")


def main():
    import argparse
    import hashlib
    from pathlib import Path
    parser = argparse.ArgumentParser(description="Compare an explicitly selected interface SOURCE baseline; does not declare a freeze or prove a binary.")
    parser.add_argument("--baseline", type=Path, required=True,
                        help="reviewed directory containing openapi.json, cli-json.txt, diff-v1.schema.json and actor.wit")
    parser.add_argument("--candidate-root", type=Path, required=True)
    args = parser.parse_args()
    def bounded(path):
        with path.open("rb") as source:
            content = source.read((2 << 20) + 1)
        if len(content) > 2 << 20:
            raise BreakingContract("source contract exceeds 2 MiB")
        return content.decode("utf-8")
    before = {name: bounded(args.baseline / name) for name in
              ("openapi.json", "cli-json.txt", "diff-v1.schema.json", "actor.wit")}
    after = {
        "openapi.json": bounded(args.candidate_root / "docs/reference/openapi.json"),
        "cli-json.txt": bounded(args.candidate_root / "docs/reference/json.md"),
        "diff-v1.schema.json": bounded(args.candidate_root / "docs/reference/diff-v1.schema.json"),
        "actor.wit": bounded(args.candidate_root / "wit/kronik-actor.wit"),
    }
    operations = api_compatible(json.loads(before["openapi.json"]), json.loads(after["openapi.json"]))
    commands = cli_compatible(before["cli-json.txt"], after["cli-json.txt"])
    old_diff, new_diff = json.loads(before["diff-v1.schema.json"]), json.loads(after["diff-v1.schema.json"])
    schema_compatible(old_diff, new_diff, old_diff, new_diff, "response", "kronik.diff/v1")
    wit_compatible(before["actor.wit"], after["actor.wit"])
    identities = lambda entries: {name: hashlib.sha256(text.encode()).hexdigest() for name, text in entries.items()}
    print(json.dumps({"format": "kronik.interface-source-comparison/v1", "kind": "source-comparison-only",
                      "baseline_sha256": identities(before), "candidate_sha256": identities(after),
                      "api_operations": operations, "cli_commands": commands, "passed": True}))


if __name__ == "__main__":
    import sys
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"interface source compatibility: {error}", file=sys.stderr)
        sys.exit(1)
