"""Parser boundary tests; actual CLI/API/WIT inventories use the built binary."""
import json
from pathlib import Path
import runpy
import unittest

SURFACE = runpy.run_path(str(Path(__file__).resolve().parents[1] / "check-doc-surface.py"))


class DocumentationSurfaceTest(unittest.TestCase):
    def test_duplicate_sections_are_not_silently_overwritten(self):
        with self.assertRaises(SURFACE["InvalidSurface"]):
            SURFACE["sections"]("## state\nfirst\n## state\nsecond\n")

    def test_nested_headings_remain_inside_their_interface(self):
        result = SURFACE["sections"]("## state\ntext\n### example\nusage\n## sql\nnext\n")
        self.assertIn("usage", result["state"])
        self.assertNotIn("next", result["state"])

    def test_markdown_output_heading_inside_example_does_not_cut_real_section(self):
        text = "## kronik diff show\n```text\n$ kronik diff show sample\n## Responses\nchanged\n```\n## next\n"
        body = SURFACE["sections"](text)["kronik diff show"]
        self.assertTrue(SURFACE["command_example"](body, ["diff", "show"]))
        self.assertNotIn("Responses", SURFACE["sections"](text))

    def test_declaration_is_not_a_command_usage_example(self):
        self.assertFalse(SURFACE["command_example"]("`kronik actors list`", ["actors", "list"]))
        self.assertFalse(SURFACE["command_example"]("```sh\nkronik actors inspect counter/a\n```\n", ["actors", "list"]))

    def test_global_options_and_pipeline_do_not_hide_real_examples(self):
        body = "```sh\nprintf '%s' text | \\\n  kronik --socket /owned/api.sock --json secret set fixture-key --reason 'known fixture'\n```\n"
        self.assertTrue(SURFACE["command_example"](body, ["secret", "set"]))

    def test_unbalanced_shell_quotes_do_not_count_as_examples(self):
        self.assertFalse(SURFACE["command_example"]("```sh\nkronik deploy 'broken\n```\n", ["deploy"]))

    def test_wit_records_comments_and_exports_do_not_confuse_function_inventory(self):
        text = """
        // interface not-real { ignored: func(); }
        interface state {
          record item { key: string, value: list<u8> }
          get: func(key: string) -> option<list<u8>>;
        }
        interface handler { handle: func(); }
        world actor { import state; export handler; }
        """
        self.assertEqual([("handler", "handle"), ("state", "get")], SURFACE["wit_functions"](text))

    def test_empty_unterminated_or_duplicate_wit_inventory_fails_closed(self):
        for text in ("world actor {}", "interface x { get: func();", "interface x { get: func(); get: func(); }"):
            with self.subTest(text=text), self.assertRaises(SURFACE["InvalidSurface"]):
                SURFACE["wit_functions"](text)

    def test_actual_api_dispatch_not_scope_patterns_defines_operations(self):
        source = '''
        fn required_scope(method, segs) { match (method, segs) { ("POST", ["v1", "not-a-route"]) => Admin } }
        async fn route(req, segs) {
            match (req.method.as_str(), segs.as_slice()) {
                ("GET", ["v1", "actors", kind, key]) => self.inspect(kind, key),
                _ => Err("not found"),
            }
        }
        '''
        self.assertEqual({"GET /v1/actors/{}/{}"}, SURFACE["routed_api"](source))

    def test_rust_literals_and_nested_comments_cannot_invent_api_routes(self):
        source = '''
        const EXAMPLE: &str = "fn route_fake() { not actual code }";
        /* outer { /* nested } */ ignored } */
        fn route(req, segs) {
            // ("POST", ["v1", "commented"]) => fake(),
            match (req.method.as_str(), segs) {
                ("GET", ["v1", "real"]) => handler(r###"{ literal }"###, '}'),
                _ => None,
            }
        }
        '''
        self.assertEqual({"GET /v1/real"}, SURFACE["routed_api"](source))

    def test_alternative_method_and_path_patterns_are_all_covered(self):
        source = '''
        fn route(req, segs) {
            match (req.method.as_str(), segs) {
                ("GET" | "HEAD", ["v1", "health"]) | ("POST", ["v1", "probe"]) => handler(),
                _ => None,
            }
        }
        '''
        self.assertEqual({"GET /v1/health", "HEAD /v1/health", "POST /v1/probe"}, SURFACE["routed_api"](source))

    def test_unsupported_path_patterns_cannot_silently_narrow_the_inventory(self):
        source = '''
        fn route(req, segs) {
            match (req.method.as_str(), segs) {
                ("GET", ["v1", remaining @ ..]) => handler(remaining),
                _ => None,
            }
        }
        '''
        with self.assertRaisesRegex(SURFACE["InvalidSurface"], "unsupported API path segment"):
            SURFACE["routed_api"](source)

    def test_new_dispatch_convention_requires_an_explicit_inventory_update(self):
        with self.assertRaisesRegex(SURFACE["InvalidSurface"], "unsupported API route dispatch"):
            SURFACE["routed_api"]('fn route(req, segs) { if req.method == "GET" { handler() } }')

    def test_duplicate_real_routes_are_not_silently_deduplicated(self):
        source = '''
        fn route(req, segs) {
            match (req.method.as_str(), segs) {
                ("GET", ["v1", "same", first]) => handler(),
                ("GET", ["v1", "same", second]) => other(),
                _ => None,
            }
        }
        '''
        with self.assertRaisesRegex(SURFACE["InvalidSurface"], "duplicate actual API route"):
            SURFACE["routed_api"](source)

    def test_block_arms_without_commas_do_not_hide_following_real_routes(self):
        source = '''
        fn route(req, segs) {
            match (req.method.as_str(), segs) {
                ("GET", ["v1", "first"]) => { handler() }
                ("GET", ["v1", "second"]) => { another() }
                ("POST", ["v1", "third"]) => final_handler(),
                _ => None,
            }
        }
        '''
        self.assertEqual({"GET /v1/first", "GET /v1/second", "POST /v1/third"}, SURFACE["routed_api"](source))

    def test_real_prebody_stream_style_counts_both_get_operations(self):
        server = '''
        if matches!(req.path.as_str(), "/v1/events/stream" | "/v1/events/ws") {
            return Ok(crate::event_stream::serve(api, req, captured, incoming).await);
        }
        '''
        handler = '''
        if request.method != "GET" || req.headers().contains_key(TRANSFER_ENCODING) {
            return Err(ApiError::new(BadRequest, "GET without a body"));
        }
        '''
        self.assertEqual({"GET /v1/events/stream", "GET /v1/events/ws"}, SURFACE["event_stream_api"](server, handler))

    def test_captured_stream_call_is_the_same_dispatch_shape(self):
        server = '''
        if matches!(req.path.as_str(), "/v1/events/stream" | "/v1/events/ws") {
            let incoming = hyper::Request::from_parts(parts, body);
            return Ok(crate::event_stream::serve_captured(api, req, captured, incoming).await);
        }
        '''
        handler = '''
        if request.method != "GET" || req.headers().contains_key(TRANSFER_ENCODING) {
            return Err(ApiError::new(BadRequest, "GET without a body"));
        }
        '''
        self.assertEqual({"GET /v1/events/stream", "GET /v1/events/ws"}, SURFACE["event_stream_api"](server, handler))

    def test_captured_stream_call_outside_the_literal_guard_is_rejected(self):
        server = '''
        if req.path == "/v1/events/stream" {
            return Ok(crate::event_stream::serve_captured(api, req, captured, incoming).await);
        }
        '''
        with self.assertRaisesRegex(SURFACE["InvalidSurface"], "unsupported server event-stream dispatch"):
            SURFACE["event_stream_api"](server, "")

    def test_ui_asset_literal_arms_become_get_and_head_routes(self):
        root = self.temporary_ui_mapping('''
        pub fn asset(path: &str) -> Option<Asset> {
            match path {
                "/ui" | "/ui/" => (("text/html; charset=utf-8"), include_bytes!("../ui/index.html")),
                "/ui/app.css" => (("text/css"), include_bytes!("../ui/app.css")),
                _ => None,
            }
        }
        ''')
        self.assertEqual(
            {"GET /ui", "HEAD /ui", "GET /ui/", "HEAD /ui/", "GET /ui/app.css", "HEAD /ui/app.css"},
            SURFACE["ui_asset_api"](root),
        )

    def test_ui_asset_mapping_without_literal_arms_is_rejected(self):
        root = self.temporary_ui_mapping('''
        pub fn asset(path: &str) -> Option<Asset> {
            builtins().get(path).copied()
        }
        ''')
        with self.assertRaisesRegex(SURFACE["InvalidSurface"], "no literal path arms"):
            SURFACE["ui_asset_api"](root)

    def temporary_ui_mapping(self, source):
        import tempfile
        root = Path(tempfile.mkdtemp()) / "crates" / "kronik-ui" / "src"
        root.mkdir(parents=True)
        (root / "lib.rs").write_text(source)
        return root.parents[2]

    def test_special_stream_method_must_be_proved_by_the_handler(self):
        server = '''
        if matches!(req.path.as_str(), "/v1/events/stream") {
            return Ok(crate::event_stream::serve(api, req, captured, incoming).await);
        }
        '''
        with self.assertRaisesRegex(SURFACE["InvalidSurface"], "explicit GET rejection"):
            SURFACE["event_stream_api"](server, "fn serve() { arbitrary() }")

    def test_changed_special_dispatch_is_not_silently_omitted(self):
        server = '''
        if req.path == "/v1/events/stream" {
            return Ok(crate::event_stream::serve(api, req, captured, incoming).await);
        }
        '''
        with self.assertRaisesRegex(SURFACE["InvalidSurface"], "unsupported server event-stream dispatch"):
            SURFACE["event_stream_api"](server, "")

    def test_conditional_method_rejection_is_not_a_get_only_contract(self):
        server = '''
        if matches!(req.path.as_str(), "/v1/events/stream") {
            return Ok(crate::event_stream::serve(api, req, captured, incoming).await);
        }
        '''
        handler = 'if request.method != "GET" && body_present { return Err(error); }'
        with self.assertRaisesRegex(SURFACE["InvalidSurface"], "unsupported event-stream method rejection"):
            SURFACE["event_stream_api"](server, handler)

    def test_http_example_matches_actual_parameter_position_and_query(self):
        body = "```http\nGET /v1/turns/main:0:1?format=json HTTP/1.1\nHost: kronik\n```\n"
        self.assertTrue(SURFACE["api_example"](body, "GET", "/v1/turns/{id}"))
        self.assertFalse(SURFACE["api_example"](body, "GET", "/v1/turns/{id}/trace"))

    def test_cursor_pipeline_counts_its_explicit_post_not_the_first_get(self):
        body = ("```sh\n"
                "curl --request GET --url 'http://kronik/v1/events?source=actor-native&limit=1' |\n"
                "curl --request POST --data-binary @- --url http://kronik/v1/events/webhooks/owned/replay\n```\n")
        self.assertTrue(SURFACE["api_example"](body, "POST", "/v1/events/webhooks/{name}/replay"))
        self.assertFalse(SURFACE["api_example"](body, "POST", "/v1/events"))

    def test_payload_url_is_not_the_documented_transport_target(self):
        body = "```sh\ncurl --request POST --url http://kronik/v1/health --data '{\"url\":\"http://kronik/v1/fleet/enroll\"}'\n```\n"
        self.assertFalse(SURFACE["api_example"](body, "POST", "/v1/fleet/enroll"))

    def test_wrong_method_or_bare_endpoint_mention_is_not_usage(self):
        for verb in ("GET", "post"):
            body = f"```sh\ncurl --request {verb} --url http://kronik/v1/fleet/enroll\n```\n"
            with self.subTest(verb=verb):
                self.assertFalse(SURFACE["api_example"](body, "POST", "/v1/fleet/enroll"))
        self.assertFalse(SURFACE["api_example"]("`POST /v1/fleet/enroll`", "POST", "/v1/fleet/enroll"))

    def test_real_public_dispatch_and_schema_have_the_same_method_path_shapes(self):
        root = Path(__file__).resolve().parents[2]
        actual = SURFACE["actual_api"](root)
        schema = json.loads((root / "docs/reference/openapi.json").read_text())
        declared = {SURFACE["normalized_operation"](method.upper() + " " + path)
                    for path, item in schema["paths"].items() for method in item
                    if method.lower() in ("get", "post", "put", "patch", "delete", "head", "options")}
        self.assertTrue(actual)
        self.assertEqual(declared, actual)


if __name__ == "__main__":
    unittest.main()
