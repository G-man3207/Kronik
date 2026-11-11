"""The CLI overview must name every command that takes Mutation.

The parenthetical in docs/reference/cli.md claims to be every mutation that
requires --reason and supports --dry-run. This check reads the clap surface
in crates/kronik/src/cli and fails if a new command flattens Mutation without
being named there.
"""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
CLI = ROOT / "crates" / "kronik" / "src" / "cli"
REFERENCE = ROOT / "docs" / "reference" / "cli.md"
OPERATIONS = ROOT / "docs" / "guides" / "operations.md"
SOURCE_SET = ("openbao", "aws", "gcp", "azure", "pkcs11")


class SurfaceError(ValueError):
    pass


class Scanner:
    def __init__(self, text):
        self.text = text
        self.n = len(text)
        self.i = 0

    def peek(self):
        return self.text[self.i] if self.i < self.n else ""

    def starts(self, token):
        return self.text.startswith(token, self.i)

    def skip(self):
        while self.i < self.n:
            if self.starts("//"):
                end = self.text.find("\n", self.i)
                self.i = self.n if end < 0 else end + 1
            elif self.starts("/*"):
                end = self.text.find("*/", self.i + 2)
                if end < 0:
                    raise SurfaceError("unterminated block comment")
                self.i = end + 2
            elif self.text[self.i] in " \t\r\n":
                self.i += 1
            else:
                break

    def line(self):
        return self.text.count("\n", 0, self.i) + 1

    def skip_rust_literal(self):
        """Skip a string, character, byte literal, or lifetime. Return whether one was skipped."""
        start = self.i
        if self.peek() in "bcr":
            seen = set()
            while self.peek() in "bcr" and self.peek() not in seen:
                seen.add(self.peek())
                self.i += 1
            hashes = 0
            while self.peek() == "#":
                hashes += 1
                self.i += 1
            if self.peek() == '"':
                self.i += 1
                if hashes:
                    closer = '"' + ("#" * hashes)
                    end = self.text.find(closer, self.i)
                    if end < 0:
                        raise SurfaceError(f"unterminated raw string at line {self.line()}")
                    self.i = end + len(closer)
                else:
                    self.skip_quoted('"')
                return True
            if seen == {"b"} and hashes == 0 and self.peek() == "'":
                self.skip_char()
                return True
            self.i = start
        if self.peek() == '"':
            self.i += 1
            self.skip_quoted('"')
            return True
        if self.peek() == "'":
            self.skip_tick()
            return True
        return False

    def skip_quoted(self, quote):
        while self.i < self.n:
            char = self.text[self.i]
            self.i += 1
            if char == "\\":
                if self.i >= self.n:
                    raise SurfaceError(f"unterminated escape at line {self.line()}")
                self.i += 1
            elif char == quote:
                return
            elif char == "\n":
                raise SurfaceError(f"unterminated string at line {self.line()}")
        raise SurfaceError(f"unterminated string at line {self.line()}")

    def skip_tick(self):
        nxt = self.text[self.i + 1:self.i + 2]
        nxt2 = self.text[self.i + 2:self.i + 3]
        if nxt == "\\":
            self.skip_char()
            return
        if nxt and (nxt.isalpha() or nxt == "_") and nxt2 != "'":
            self.i += 1
            while self.peek().isalnum() or self.peek() == "_":
                self.i += 1
            return
        self.skip_char()

    def skip_char(self):
        if self.peek() != "'":
            raise SurfaceError(f"expected a character literal at line {self.line()}")
        self.i += 1
        if self.peek() == "\\":
            self.i += 1
            if self.peek() == "u":
                self.i += 1
                if self.peek() == "{":
                    end = self.text.find("}", self.i)
                    if end < 0:
                        raise SurfaceError(f"unterminated unicode escape at line {self.line()}")
                    self.i = end + 1
            elif self.peek():
                self.i += 1
            else:
                raise SurfaceError(f"unterminated character literal at line {self.line()}")
        elif self.peek() and self.peek() != "\n":
            self.i += 1
        else:
            raise SurfaceError(f"unterminated character literal at line {self.line()}")
        if self.peek() != "'":
            raise SurfaceError(f"unterminated character literal at line {self.line()}")
        self.i += 1

    def take_balanced(self, open_char, close_char):
        if self.peek() != open_char:
            raise SurfaceError(f"expected {open_char}")
        start = self.i
        depth = 0
        while self.i < self.n:
            if self.starts("//") or self.starts("/*"):
                self.skip()
                continue
            if self.skip_rust_literal():
                continue
            char = self.peek()
            if close_char == ">" and char == ">" and self.i > start and self.text[self.i - 1] == "-":
                self.i += 1
                continue
            if char == open_char:
                depth += 1
            elif char == close_char:
                depth -= 1
                self.i += 1
                if depth == 0:
                    return self.text[start:self.i]
                continue
            self.i += 1
        raise SurfaceError(f"unterminated {open_char}{close_char} group")

    def attribute(self):
        self.skip()
        if not self.starts("#["):
            return None
        self.i += 1
        return "#[" + self.take_balanced("[", "]")[1:]

    def attributes(self):
        found = []
        while True:
            attr = self.attribute()
            if attr is None:
                return found
            found.append(attr)

    def ident(self):
        self.skip()
        match = re.match(r"[A-Za-z_][A-Za-z0-9_]*", self.text[self.i :])
        if not match:
            raise SurfaceError(f"expected an identifier near {self.text[self.i:self.i + 40]!r}")
        self.i += match.end()
        return match.group(0)

    def skip_item(self):
        """Skip a non-type item, including its body."""
        depth = 0
        seen_brace = False
        while self.i < self.n:
            if self.starts("//") or self.starts("/*"):
                self.skip()
                continue
            if self.skip_rust_literal():
                continue
            char = self.peek()
            if char == "{":
                depth += 1
                seen_brace = True
            elif char == "}":
                depth -= 1
                if depth < 0:
                    raise SurfaceError("unbalanced brace while skipping an item")
                if depth == 0 and seen_brace:
                    self.i += 1
                    self.skip()
                    if self.peek() == ";":
                        self.i += 1
                    return
            elif char == ";" and depth == 0:
                self.i += 1
                return
            self.i += 1
        raise SurfaceError("file ended while skipping an item")

    def parse_type(self):
        self.skip()
        start = self.i
        angle = paren = 0
        while self.i < self.n:
            if self.starts("//") or self.starts("/*"):
                self.skip()
                continue
            char = self.peek()
            if self.skip_rust_literal():
                continue
            if char == "<":
                angle += 1
            elif char == ">":
                angle -= 1
            elif char == "(":
                paren += 1
            elif char == ")":
                if paren == 0 and angle == 0:
                    break
                paren -= 1
            elif char in ",}" and angle == 0 and paren == 0:
                break
            self.i += 1
        parsed = " ".join(self.text[start:self.i].split())
        if not parsed:
            raise SurfaceError("missing field type")
        return parsed

    def parse_fields(self):
        fields = []
        while True:
            self.skip()
            if self.peek() == "}":
                self.i += 1
                return fields
            attrs = self.attributes()
            self.skip()
            if self.starts("pub"):
                self.ident()
                self.skip()
                if self.peek() == "(":
                    self.take_balanced("(", ")")
                    self.skip()
            name = self.ident()
            self.skip()
            if self.peek() != ":":
                raise SurfaceError(f"field {name} has no type")
            self.i += 1
            fields.append({
                "name": name,
                "type": self.parse_type(),
                "flatten": any(re.search(r"#\[command\([^\)]*\bflatten\b", attr) for attr in attrs),
                "subcommand": any(re.search(r"#\[command\(\s*subcommand\s*\)\]", attr) for attr in attrs),
            })
            self.skip()
            if self.peek() == ",":
                self.i += 1

    def parse_variants(self, rename_all):
        variants = []
        while True:
            self.skip()
            if self.peek() == "}":
                self.i += 1
                return variants
            attrs = self.attributes()
            name = self.ident()
            self.skip()
            payload = None
            fields = None
            if self.peek() == "(":
                body = self.take_balanced("(", ")")[1:-1].strip()
                parts = [part.strip() for part in split_top_level(body, ",")]
                if len(parts) != 1 or not parts[0]:
                    raise SurfaceError(f"variant {name} has an unsupported payload")
                payload = " ".join(parts[0].split())
            elif self.peek() == "{":
                self.i += 1
                fields = self.parse_fields()
            elif self.peek() == "=":
                raise SurfaceError(f"variant {name} has an explicit discriminant")
            self.skip()
            if self.peek() == ",":
                self.i += 1
            variants.append({
                "name": name,
                "command": command_name(name, attrs, rename_all),
                "payload": payload,
                "fields": fields,
                "subcommand": any(re.search(r"#\[command\(\s*subcommand\s*\)\]", attr) for attr in attrs),
            })


def split_top_level(text, separator):
    parts = []
    start = depth = 0
    i = 0
    while i < len(text):
        char = text[i]
        if char in "([{<":
            depth += 1
        elif char in ")]}>":
            depth -= 1
        elif char == separator and depth == 0:
            parts.append(text[start:i])
            start = i + 1
        i += 1
    parts.append(text[start:])
    return parts


def derive_names(attributes):
    names = set()
    for attr in attributes:
        match = re.search(r"#\[derive\((.*)\)\]", attr, re.S)
        if not match:
            continue
        for part in split_top_level(match.group(1), ","):
            names.add(part.strip().split("::")[-1])
    return names


def rename_all(attributes):
    found = None
    for attr in attributes:
        match = re.search(r"\brename_all\s*=\s*\"([^\"]+)\"", attr)
        if match:
            if found and found != match.group(1):
                raise SurfaceError("conflicting rename_all attributes")
            found = match.group(1)
    return found or "kebab-case"


def command_name(variant, attributes, style):
    for attr in attributes:
        if not attr.startswith("#[command(") and not attr.startswith("#[clap("):
            continue
        match = re.search(r"\bname\s*=\s*\"([^\"]+)\"", attr)
        if match:
            return match.group(1)
    if style != "kebab-case":
        raise SurfaceError(f"unsupported command rename {style}")
    kebab = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", variant)
    kebab = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1-\2", kebab)
    return kebab.lower()


def module_of(path):
    return "" if path.name == "mod.rs" else path.stem


def parse_file(path, text):
    scan = Scanner(text)
    items = {}
    module = module_of(path) if isinstance(path, Path) else module_of(Path(path))
    while True:
        scan.skip()
        if scan.i >= scan.n:
            return module, items
        attributes = scan.attributes()
        scan.skip()
        public = False
        if scan.starts("pub"):
            public = True
            scan.ident()
            scan.skip()
            if scan.peek() == "(":
                scan.take_balanced("(", ")")
                scan.skip()
        if scan.starts("struct ") or scan.starts("enum "):
            kind = "struct" if scan.starts("struct ") else "enum"
            scan.i += len(kind) + 1
            name = scan.ident()
            scan.skip()
            if scan.peek() == "<":
                if {"Args", "Subcommand"}.intersection(derive_names(attributes)):
                    raise SurfaceError(f"generic {kind} {name} is not a supported command type")
                scan.take_balanced("<", ">")
                scan.skip()
                if scan.peek() == "(":
                    scan.take_balanced("(", ")")
                    scan.skip()
                if scan.peek() == "{":
                    scan.take_balanced("{", "}")
                elif scan.peek() == ";":
                    scan.i += 1
                else:
                    raise SurfaceError(f"generic {kind} {name} has no body")
                continue
            if kind == "struct" and scan.peek() == ";":
                scan.i += 1
                fields = []
            elif kind == "struct" and scan.peek() == "(":
                body = scan.take_balanced("(", ")")[1:-1]
                fields = [{
                    "name": "",
                    "type": " ".join(part.split()),
                    "flatten": False,
                    "subcommand": False,
                } for part in split_top_level(body, ",") if part.strip()]
                scan.skip()
                if scan.peek() == ";":
                    scan.i += 1
            else:
                if scan.peek() != "{":
                    raise SurfaceError(f"{kind} {name} has no body")
                scan.i += 1
                if kind == "struct":
                    fields = scan.parse_fields()
                    variants = None
                else:
                    fields = None
                    variants = scan.parse_variants(rename_all(attributes))
            key = (module, name)
            if key in items:
                raise SurfaceError(f"duplicate type {name} in {module or 'cli'}")
            items[key] = {
                "kind": kind,
                "name": name,
                "module": module,
                "derives": derive_names(attributes),
                "fields": fields,
                "variants": variants,
                "public": public,
            }
            continue
        scan.skip_item()


def load_items(files):
    items = {}
    for path, text in files.items():
        _, parsed = parse_file(path, text)
        overlap = set(items).intersection(parsed)
        if overlap:
            raise SurfaceError(f"duplicate command types: {sorted(overlap)}")
        items.update(parsed)
    return items


def is_mutation(type_name):
    return type_name.split("::")[-1] == "Mutation"


def resolve(items, module, type_name):
    type_name = " ".join(type_name.split())
    if is_mutation(type_name):
        return None
    if "::" in type_name:
        parts = type_name.split("::")
        if len(parts) != 2 or parts[0] in ("super", "crate", "self"):
            raise SurfaceError(f"unsupported command type path {type_name}")
        key = (parts[0], parts[1])
    else:
        key = (module, type_name)
    if key not in items:
        matches = [item for item in items.values() if item["name"] == type_name.split("::")[-1]]
        if len(matches) == 1:
            return matches[0]
        raise SurfaceError(f"cannot resolve {type_name} from {module or 'cli'}")
    return items[key]


def carries_mutation(items, item, stack):
    identity = (item["module"], item["name"])
    if identity in stack:
        raise SurfaceError(f"cyclic flattened args at {item['name']}")
    for field in item["fields"] or []:
        if is_mutation(field["type"]):
            return True
        if not field["flatten"]:
            continue
        target = resolve(items, item["module"], field["type"])
        if target is None:
            return True
        if "Args" not in target["derives"] or target["kind"] != "struct":
            raise SurfaceError(f"flattened {field['type']} is not an Args struct")
        if carries_mutation(items, target, stack | {identity}):
            return True
    return False


def variant_carries(items, module, variant):
    if any(field["subcommand"] for field in variant["fields"] or []):
        raise SurfaceError(f"{variant['name']} mixes fields with a subcommand")
    fake = {"module": module, "name": variant["name"], "fields": variant["fields"], "derives": {"Args"}}
    return carries_mutation(items, fake, set())


def walk(items, item, prefix, found):
    if item["kind"] != "enum" or "Subcommand" not in item["derives"]:
        raise SurfaceError(f"{item['name']} is not a subcommand enum")
    for variant in item["variants"]:
        path = [*prefix, variant["command"]]
        if variant["payload"]:
            target = resolve(items, item["module"], variant["payload"])
            if target is None:
                raise SurfaceError(f"{' '.join(path)} takes Mutation directly")
            if "Subcommand" in target["derives"]:
                walk(items, target, path, found)
            elif "Args" in target["derives"] and target["kind"] == "struct":
                if carries_mutation(items, target, set()):
                    found.add(" ".join(path))
            else:
                raise SurfaceError(f"{' '.join(path)} has an unsupported payload {variant['payload']}")
        elif variant["fields"] is not None and variant_carries(items, item["module"], variant):
            found.add(" ".join(path))


def mutation_commands(files):
    items = load_items(files)
    command = items.get(("", "Command"))
    if command is None:
        raise SurfaceError("cli Command enum was not found")
    found = set()
    walk(items, command, [], found)
    if not found:
        raise SurfaceError("no Mutation commands were found")
    return found


def repo_files():
    return {path: path.read_text() for path in sorted(CLI.glob("*.rs"))}


def overview_commands(text):
    match = re.search(r"Every mutation \((.*?)\) requires `--reason`", text, re.S)
    if not match:
        raise SurfaceError("missing exhaustive mutation overview sentence")
    names = re.findall(r"`([^`]+)`", match.group(1))
    if not names or len(names) != len(set(names)):
        raise SurfaceError(f"overview mutation list is empty or repeated: {names}")
    window = text[match.start():match.start() + 1800]
    for required in (
        "supports `--dry-run`",
        "`replay` writes only in its",
        "`send --fork` only in the fork",
        "have\nno dry run",
        "`restore` and `upgrade check` are offline",
        "so they take no `--reason`",
    ):
        if required not in window:
            raise SurfaceError(f"overview no longer states {required!r}")
    return set(names)


def section(text, heading):
    match = re.search(rf"^## {re.escape(heading)}\n(.*?)(?=^## |\Z)", text, re.S | re.M)
    if not match:
        raise SurfaceError(f"missing section {heading}")
    return match.group(1)


def flat(text):
    return re.sub(r"\s+", " ", text)


def source_set(text):
    found = re.findall(r"openbao\|aws\|gcp\|azure\|pkcs11", text)
    if not found:
        raise SurfaceError("source set openbao|aws|gcp|azure|pkcs11 is absent")
    return set(SOURCE_SET)


class MutationOverviewTest(unittest.TestCase):
    def test_parser_follows_nested_flattened_and_shared_mutation_args(self):
        files = {
            "mod.rs": """
                #[derive(Debug, Subcommand)]
                pub enum Command {
                    Deploy(DeployArgs),
                    Secret(SecretCommand),
                    Approve(fork::ProposalArgs),
                    Promote(fork::ProposalArgs),
                    Replay(fork::ReplayArgs),
                }
                #[derive(Debug, Args)]
                pub struct DeployArgs {
                    #[command(flatten)]
                    mutation: Mutation,
                }
                #[derive(Debug, Subcommand)]
                pub enum SecretCommand {
                    Link {
                        #[command(flatten)]
                        mutation: Mutation,
                    },
                    List,
                }
            """,
            "fork.rs": """
                #[derive(Debug, Args)]
                pub struct ProposalArgs {
                    #[command(flatten)]
                    mutation: Mutation,
                }
                #[derive(Debug, Args)]
                pub struct ReplayArgs {
                    #[arg(long)]
                    reason: Option<String>,
                }
            """,
        }
        self.assertEqual(
            mutation_commands(files),
            {"deploy", "secret link", "approve", "promote"},
        )

    def test_parser_rejects_an_unresolved_command_payload(self):
        with self.assertRaises(SurfaceError):
            mutation_commands({"mod.rs": """
                #[derive(Debug, Subcommand)]
                pub enum Command { Missing(MissingArgs), }
            """})

    def test_overview_names_every_mutation_command_and_no_others(self):
        commands = mutation_commands(repo_files())
        documented = overview_commands(REFERENCE.read_text())
        self.assertEqual(
            documented,
            commands,
            "overview mutation list differs from commands that take Mutation:\n"
            f"missing {sorted(commands - documented)}\n"
            f"extra {sorted(documented - commands)}",
        )
        self.assertNotIn("replay", commands)
        self.assertIn("send", commands)
        self.assertNotIn("restore", documented)
        self.assertNotIn("upgrade check", documented)

    def test_reason_required_row_does_not_contradict_the_overview(self):
        row = next(
            line for line in OPERATIONS.read_text().splitlines()
            if line.startswith("| `REASON_REQUIRED`")
        )
        self.assertIn("`restore` and `upgrade check`", row)
        self.assertIn("take no `--reason`", row)
        mentioned = set(re.findall(r"`([^`]+)`", row))
        inventory = {
            name for name in mentioned
            if not name.startswith("--") and name not in {"REASON_REQUIRED", "restore", "upgrade check"}
        }
        if inventory:
            self.assertEqual(inventory, mutation_commands(repo_files()))
        self.assertNotRegex(row, r"replay[^.\n]*take no `--reason`")
        self.assertNotRegex(row, r"send --fork[^.\n]*take no `--reason`")

    def test_secret_link_commits_unless_the_run_is_a_dry_run(self):
        body = section(REFERENCE.read_text(), "kronik secret link")
        prose, _, example = body.partition("```")
        prose = flat(prose)
        self.assertIn("does not set the remote provider's value", prose)
        self.assertIn("SecretLink", prose)
        self.assertIn("without `--dry-run`", prose)
        self.assertIn("commits", prose)
        self.assertIn("`--dry-run` only previews", prose)
        self.assertNotIn("does not establish a committed link", prose)
        self.assertNotIn("does not establish a committed link", flat(body))
        self.assertIn("--dry-run", example)

    def test_keys_wrap_synopsis_and_enroll_name_the_same_sources(self):
        text = REFERENCE.read_text()
        wrap = section(text, "kronik keys wrap")
        enroll = section(text, "kronik keys enroll")
        synopsis = wrap.strip().splitlines()[0]
        self.assertIn(
            "`kronik keys wrap --source <openbao|aws|gcp|azure|pkcs11>",
            synopsis,
        )
        self.assertEqual(source_set(synopsis), source_set(enroll))
        self.assertIn("`kronik keys wrap --source pkcs11`", flat(enroll))
        self.assertIn("not a cloud KMS", flat(wrap))
        self.assertIn("not a cloud KMS", flat(enroll))
        self.assertNotRegex(flat(wrap), r"pkcs11 is a cloud KMS")
        parser = (CLI / "keys.rs").read_text()
        match = re.search(r'value_parser = \[(.*?)\]', parser, re.S)
        self.assertIsNotNone(match)
        accepted = re.findall(r'"([^"]+)"', match.group(1))
        self.assertEqual(accepted, list(SOURCE_SET))


if __name__ == "__main__":
    unittest.main()
