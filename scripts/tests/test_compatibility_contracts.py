"""Semantic boundary tests, not a declaration that today's interfaces are frozen."""
import copy
import json
from pathlib import Path
import runpy
import unittest

CONTRACTS = runpy.run_path(str(Path(__file__).resolve().parents[1] / "compatibility-contracts.py"))
Breaking = CONTRACTS["BreakingContract"]


class SchemaCompatibilityTest(unittest.TestCase):
    def compare(self, old, new, direction="response", old_document=None, new_document=None):
        CONTRACTS["schema_compatible"](old, new, old if old_document is None else old_document,
                                        new if new_document is None else new_document, direction)

    def object(self):
        return {"type": "object", "properties": {"count": {"type": "integer"}}, "required": ["count"]}

    def test_annotation_edits_do_not_change_the_wire_contract(self):
        old = self.object()
        new = {**old, "description": "different explanation", "title": "different heading", "examples": []}
        self.compare(old, new)

    def test_removed_optional_response_field_is_not_hidden_by_requiredness(self):
        old = self.object()
        old["properties"]["optional"] = {"type": "string"}
        with self.assertRaises(Breaking):
            self.compare(old, self.object())

    def test_required_output_cannot_become_optional(self):
        old, new = self.object(), self.object()
        new["required"] = []
        with self.assertRaises(Breaking):
            self.compare(old, new)

    def test_optional_request_cannot_become_required(self):
        old, new = self.object(), self.object()
        old["required"] = []
        with self.assertRaises(Breaking):
            self.compare(old, new, "request")

    def test_closed_request_object_can_gain_a_new_optional_field(self):
        old, new = self.object(), self.object()
        old["additionalProperties"] = False
        new["additionalProperties"] = False
        new["properties"]["limit"] = {"type": "integer"}
        self.compare(old, new, "request")

    def test_optional_named_request_field_cannot_narrow_old_unknown_field_values(self):
        old = {"type": "object", "additionalProperties": True}
        new = {**old, "properties": {"foo": {"type": "integer"}}}
        with self.assertRaises(Breaking):
            self.compare(old, new, "request")

    def test_named_response_field_must_satisfy_old_typed_unknown_field_contract(self):
        old = {"type": "object", "additionalProperties": {"type": "string"}}
        new = {**old, "properties": {"foo": {"type": "integer"}}}
        with self.assertRaises(Breaking):
            self.compare(old, new, "response")

    def test_declaring_a_field_with_the_same_old_unknown_field_type_is_compatible(self):
        old = {"type": "object", "additionalProperties": {"type": "string"}}
        new = {**old, "properties": {"foo": {"type": "string"}}}
        self.compare(old, new, "request")
        self.compare(old, new, "response")

    def test_response_type_or_nullability_widening_breaks_old_consumers(self):
        for after in ({"type": "string"}, {"type": ["integer", "null"]}, {"type": "number"}):
            with self.subTest(after=after), self.assertRaises(Breaking):
                self.compare({"type": "integer"}, after)

    def test_integer_requests_remain_accepted_by_a_number_schema(self):
        self.compare({"type": "integer"}, {"type": "number"}, "request")
        self.compare({"type": "number"}, {"type": "integer"})

    def test_new_response_enum_case_is_not_silently_exhaustive_safe(self):
        with self.assertRaises(Breaking):
            self.compare({"type": "string", "enum": ["allow"]}, {"type": "string", "enum": ["allow", "deny"]})

    def test_existing_request_enum_value_cannot_be_removed(self):
        with self.assertRaises(Breaking):
            self.compare({"enum": ["isolated", "continuous"]}, {"enum": ["isolated"]}, "request")

    def test_boolean_and_numeric_const_values_are_distinct_without_declared_type(self):
        for before, after in ((True, 1), (False, 0)):
            with self.subTest(before=before), self.assertRaises(Breaking):
                self.compare({"const": before}, {"const": after})

    def test_nested_enum_booleans_are_not_numeric_lookalikes(self):
        old = {"enum": [{"enabled": True, "items": [False]}]}
        new = {"enum": [{"enabled": 1, "items": [0]}]}
        for direction in ("request", "response"):
            with self.subTest(direction=direction), self.assertRaises(Breaking):
                self.compare(old, new, direction)

    def test_const_is_not_ignored_when_enum_is_also_present(self):
        with self.assertRaises(Breaking):
            self.compare({"enum": [True, 1], "const": True}, {"enum": [True, 1], "const": 1})

    def test_equal_json_numbers_remain_equal_including_nested_enum_values(self):
        self.compare({"const": 1}, {"const": 1.0})
        self.compare({"enum": [{"count": 1, "items": [False, None]}]},
                     {"enum": [{"items": [False, None], "count": 1.0}]})

    def test_typed_default_change_cannot_hide_behind_python_boolean_equality(self):
        with self.assertRaises(Breaking):
            self.compare({"type": ["boolean", "integer"], "default": True},
                         {"type": ["boolean", "integer"], "default": 1})

    def test_adding_null_default_is_not_the_same_as_absence_of_a_default(self):
        with self.assertRaises(Breaking):
            self.compare({"type": ["string", "null"]}, {"type": ["string", "null"], "default": None})

    def test_object_extensions_honor_the_old_closed_object(self):
        old, new = self.object(), self.object()
        old["additionalProperties"] = False
        new["additionalProperties"] = False
        new["properties"]["extra"] = {"type": "string"}
        with self.assertRaises(Breaking):
            self.compare(old, new)

    def test_array_item_changes_are_not_just_an_array_type_match(self):
        with self.assertRaises(Breaking):
            self.compare({"type": "array", "items": {"type": "integer"}},
                         {"type": "array", "items": {"type": "string"}})

    def test_transitive_reference_change_is_seen_even_when_parent_text_is_identical(self):
        old = {"components": {"schemas": {
            "Outer": {"type": "object", "properties": {"value": {"$ref": "#/components/schemas/Leaf"}}},
            "Leaf": {"type": "integer"}}}}
        new = copy.deepcopy(old)
        new["components"]["schemas"]["Leaf"] = {"type": "string"}
        with self.assertRaises(Breaking):
            self.compare({"$ref": "#/components/schemas/Outer"}, {"$ref": "#/components/schemas/Outer"},
                         old_document=old, new_document=new)

    def test_reference_default_is_semantic_not_description(self):
        document = {"$defs": {"Mode": {"type": "string", "enum": ["isolated", "continuous"]}}}
        old = {"$ref": "#/$defs/Mode", "default": "isolated"}
        self.compare(old, {**old, "description": "more advice"}, old_document=document, new_document=document)
        with self.assertRaises(Breaking):
            self.compare(old, {**old, "default": "continuous"}, old_document=document, new_document=document)

    def test_recursive_references_terminate_without_skipping_a_changed_leaf(self):
        old = {"$defs": {"Node": {"type": "object", "properties": {
            "value": {"type": "integer"}, "next": {"$ref": "#/$defs/Node"}}}}}
        new = copy.deepcopy(old)
        self.compare({"$ref": "#/$defs/Node"}, {"$ref": "#/$defs/Node"}, old_document=old, new_document=new)
        new["$defs"]["Node"]["properties"]["value"] = {"type": "string"}
        with self.assertRaises(Breaking):
            self.compare({"$ref": "#/$defs/Node"}, {"$ref": "#/$defs/Node"}, old_document=old, new_document=new)

    def test_unknown_changed_validation_keyword_fails_closed(self):
        with self.assertRaises(Breaking):
            self.compare({"type": "string", "pattern": "^a"}, {"type": "string", "pattern": "^b"})

    def test_missing_internal_or_external_reference_is_not_a_pass(self):
        for reference in ("#/$defs/Absent", "https://invalid.example/schema"):
            with self.subTest(reference=reference), self.assertRaises(Breaking):
                self.compare({"$ref": reference}, {"$ref": reference})

    def test_diff_schema_identity_is_a_real_constant_not_a_heading(self):
        old = {"type": "object", "properties": {"schema": {"const": "kronik.diff/v1"}}, "required": ["schema"]}
        new = copy.deepcopy(old)
        new["properties"]["schema"]["const"] = "kronik.diff/v2"
        with self.assertRaises(Breaking):
            self.compare(old, new)


class ApiCompatibilityTest(unittest.TestCase):
    def api(self):
        response = {"type": "object", "properties": {"items": {"type": "array", "items": {"type": "string"}}},
                    "required": ["items"]}
        operation = {
            "operationId": "items", "x-kronik-scope": "reader",
            "parameters": [{"name": "limit", "in": "query", "required": False,
                            "schema": {"type": "integer", "default": 10}}],
            "responses": {"200": {"content": {"application/json": {"schema": response}}}},
        }
        return {"openapi": "3.1.0", "security": [{"bearer": []}], "paths": {"/v1/items": {"get": operation}}}

    def test_new_endpoint_does_not_remove_old_operations(self):
        old = self.api()
        new = copy.deepcopy(old)
        new["paths"]["/v1/another"] = copy.deepcopy(old["paths"]["/v1/items"])
        self.assertEqual(CONTRACTS["api_compatible"](old, new), 1)

    def test_method_path_scope_status_and_parameter_boundaries(self):
        changes = [
            lambda api: api["paths"].pop("/v1/items"),
            lambda api: api["paths"]["/v1/items"].pop("get"),
            lambda api: api["paths"]["/v1/items"]["get"].update({"x-kronik-scope": "admin"}),
            lambda api: api["paths"]["/v1/items"]["get"]["responses"].pop("200"),
            lambda api: api["paths"]["/v1/items"]["get"]["parameters"][0].update({"required": True}),
            lambda api: api["paths"]["/v1/items"]["get"]["parameters"][0]["schema"].update({"default": 20}),
            lambda api: api["paths"]["/v1/items"]["get"]["parameters"][0].update({"style": "simple"}),
            lambda api: api.update({"security": []}),
        ]
        for index, change in enumerate(changes):
            old, new = self.api(), self.api()
            change(new)
            with self.subTest(change=index), self.assertRaises(Breaking):
                CONTRACTS["api_compatible"](old, new)

    def test_new_required_inherited_parameter_is_not_missed(self):
        old, new = self.api(), self.api()
        new["paths"]["/v1/items"]["parameters"] = [{"name": "tenant", "in": "header", "required": True, "schema": {"type": "string"}}]
        with self.assertRaises(Breaking):
            CONTRACTS["api_compatible"](old, new)

    def test_response_field_type_is_checked_beyond_path_inventory(self):
        old, new = self.api(), self.api()
        new["paths"]["/v1/items"]["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["items"]["items"] = {"type": "integer"}
        with self.assertRaises(Breaking):
            CONTRACTS["api_compatible"](old, new)

    def test_required_request_body_cannot_be_introduced(self):
        old, new = self.api(), self.api()
        new["paths"]["/v1/items"]["get"]["requestBody"] = {"required": True, "content": {}}
        with self.assertRaises(Breaking):
            CONTRACTS["api_compatible"](old, new)

    def test_response_header_contract_is_not_lost_in_schema_only_comparison(self):
        old, new = self.api(), self.api()
        old["paths"]["/v1/items"]["get"]["responses"]["200"]["headers"] = {
            "X-Cursor": {"required": True, "schema": {"type": "string"}}}
        with self.assertRaises(Breaking):
            CONTRACTS["api_compatible"](old, new)

    def test_changed_media_encoding_requires_explicit_compatibility_proof(self):
        old, new = self.api(), self.api()
        new["paths"]["/v1/items"]["get"]["responses"]["200"]["content"]["application/json"]["encoding"] = {"items": {"style": "form"}}
        with self.assertRaises(Breaking):
            CONTRACTS["api_compatible"](old, new)


class CliCompatibilityTest(unittest.TestCase):
    def page(self, command="actors list", value_type="integer", description="one explanation"):
        schema = {"type": "object", "properties": {"count": {"type": value_type}}, "required": ["count"], "description": description}
        error = {"type": "object", "properties": {"error": {"type": "string"}}, "required": ["error"]}
        return (f"| `kronik {command}` | [`Output`](#output) |\n"
                + "| `kronik serve` | daemon, no machine response |\n\n### Output\n\n```json\n"
                + json.dumps(schema) + "\n```\n\n### Error\n\n```json\n" + json.dumps(error) + "\n```\n")

    def test_doc_copy_changes_are_irrelevant_to_cli_schema(self):
        self.assertEqual(CONTRACTS["cli_compatible"](self.page(), self.page(description="another explanation")), 2)

    def test_command_removal_and_output_type_change_are_detected(self):
        for new in (self.page(command="actors inspect"), self.page(value_type="string")):
            with self.subTest(new=new), self.assertRaises(Breaking):
                CONTRACTS["cli_compatible"](self.page(), new)

    def test_missing_output_schema_reference_is_not_ignored(self):
        with self.assertRaises(Breaking):
            CONTRACTS["cli_contracts"](self.page().replace("(#output)", "(#absent)"))

    def test_an_extra_incompatible_output_variant_cannot_hide_behind_the_old_one(self):
        old = self.page()
        new = old.replace("[`Output`](#output)", "[`Output`](#output); [`Other`](#other)")
        new += "\n### Other\n\n```json\n" + json.dumps({"type": "string"}) + "\n```\n"
        with self.assertRaises(Breaking):
            CONTRACTS["cli_compatible"](old, new)


class WitCompatibilityTest(unittest.TestCase):
    WIT = "package kronik:actor@1.0.0; interface state { read: func(key: string) -> list<u8>; }"

    def test_comments_and_layout_do_not_change_the_abi(self):
        CONTRACTS["wit_compatible"](self.WIT, "/* outer /* inner */ done */\n" + self.WIT.replace(" ", "\n"))
        commented = "/*\npackage kronik:actor@0.0.0;\n*/\n" + self.WIT
        CONTRACTS["wit_compatible"](self.WIT, commented)
        self.assertEqual(CONTRACTS["wit_package"](commented), "kronik:actor@1.0.0")

    def test_signature_ownership_and_package_changes_are_not_silent(self):
        old = self.WIT + " interface handles { resource slot; take: func(value: borrow<slot>); }"
        for new in (old.replace("list<u8>", "string"), old.replace("borrow<slot>", "own<slot>"), old.replace("@1.0.0", "@2.0.0")):
            with self.subTest(new=new), self.assertRaises(Breaking):
                CONTRACTS["wit_compatible"](old, new)

    def test_unterminated_comment_is_not_an_equal_abi(self):
        with self.assertRaises(Breaking):
            CONTRACTS["wit_compatible"](self.WIT, self.WIT + " /* incomplete")


class MigrationAndPolicyBoundaryTest(unittest.TestCase):
    def rejection(self):
        # Synthetic decoder input only; never a real product/adapter receipt.
        return {"error": {"code": "IMPORT_NOT_ALLOWED", "message": "unsupported kronik:actor/state@0.1.0",
                          "hint": "Rebuild for kronik:actor@1.0.0 using kronik build."}}

    def test_only_actual_version_specific_error_and_migration_instruction_qualify(self):
        self.assertTrue(CONTRACTS["migration_rejection"](self.rejection(), "kronik:actor@0.1.0", "kronik:actor@1.0.0"))
        for field, value in (("code", "BAD_REQUEST"), ("message", "invalid component"),
                             ("hint", "only kronik:actor and deterministic WASI are allowed")):
            error = self.rejection()
            error["error"][field] = value
            with self.subTest(field=field):
                self.assertFalse(CONTRACTS["migration_rejection"](error, "kronik:actor@0.1.0", "kronik:actor@1.0.0"))
        self.assertFalse(CONTRACTS["migration_rejection"](self.rejection(), "kronik:actor@0.1.0", "kronik:actor@0.1.0"))

    def test_real_exit_status_cannot_be_replaced_by_error_shaped_stdout(self):
        CONTRACTS["deployment_result"](0, {"epoch": 1})
        CONTRACTS["deployment_result"](1, self.rejection())
        for status, value in ((0, self.rejection()), (1, {"epoch": 1}), (2, self.rejection()), (-15, self.rejection())):
            with self.subTest(status=status), self.assertRaises(Breaking):
                CONTRACTS["deployment_result"](status, value)

    def test_policy_checks_actions_errors_and_required_fields_not_error_wording(self):
        expected = {"id": "error", "outcome": "require_approval",
                    "fired": [{"name": "missing", "action": "require_approval"}], "errors": ["missing"]}
        actual = {"outcome": "require_approval", "fired": copy.deepcopy(expected["fired"]),
                  "errors": [{"name": "missing", "message": "first explanation"}]}
        CONTRACTS["policy_result_compatible"](expected, actual)
        actual["errors"][0]["message"] = "another explanation"
        CONTRACTS["policy_result_compatible"](expected, actual)
        for changed in ({**actual, "outcome": "allow"}, {**actual, "fired": []}, {**actual, "errors": []},
                        {key: value for key, value in actual.items() if key != "fired"}):
            with self.subTest(changed=changed), self.assertRaises(Breaking):
                CONTRACTS["policy_result_compatible"](expected, changed)


if __name__ == "__main__":
    unittest.main()
