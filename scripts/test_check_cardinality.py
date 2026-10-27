import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from check_cardinality import main, query_labels, scan_repository


class CardinalityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def write(self, name, content):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def scan(self):
        findings, errors, monitored = scan_repository(self.root)
        self.assertEqual(errors, [])
        return findings, monitored

    def cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main([str(self.root), *args])
        return code, out.getvalue(), err.getvalue()

    def test_no_monitoring_skips_even_with_application_ids(self):
        self.write("Main.java", 'class Main { String userId = "request_id"; }')
        self.assertEqual(self.cli()[0], 0)
        self.assertIn("SKIP:", self.cli()[1])

    def test_rule_queries_and_normalized_names(self):
        self.write("rules.yml", '''groups:
  - name: alerts
    rules:
      - alert: BadLabels
        expr: rate(http_requests_total{user_id!="", requestID=~".+"}[5m]) > 1
''')
        findings, monitored = self.scan()
        self.assertEqual({f.label for f in findings}, {"user_id", "requestID"})
        self.assertEqual({f.line for f in findings}, {5})
        self.assertEqual(monitored, 1)
        self.assertEqual(self.cli()[0], 1)

    def test_multiline_query_and_grouping(self):
        for style in ("|", ">"):
            with self.subTest(style=style):
                self.write("alert.yaml", f'''expr: {style}
  sum by (user_id) (
    requests_total{{request_id!~"ignored"}}
  )
''')
                findings, _ = self.scan()
                self.assertEqual({f.label for f in findings}, {"user_id", "request_id"})

    def test_grafana_json_decodes_escaped_strings_and_variables(self):
        self.write("dashboard.json", json.dumps({
            "panels": [{"targets": [{"expr": 'rate(requests_total{request_id="$request"}[5m])'}]}],
            "templating": {"list": [{"query": "label_values(requests_total, user_id)"}]},
        }, indent=2))
        findings, _ = self.scan()
        self.assertEqual({f.label for f in findings}, {"user_id", "request_id"})

    def test_grafana_loki_panel_is_ignored(self):
        self.write("dashboard.json", json.dumps({"panels": [{
            "datasource": {"type": "loki", "uid": "logs"},
            "targets": [{"expr": '{user_id="1"} |= "error"'}],
        }]}))
        self.assertEqual(self.scan()[0], [])

    def test_safe_labels_and_unrelated_metadata_pass(self):
        self.write("safe.yaml", '''expr: sum by (method, status) (requests_total{route="/users/{user_id}", status="200"})
labels:
  user_id: alert-owner
annotations:
  description: request_id is available in logs
''')
        self.assertEqual(self.scan(), ([], 1))

    def test_comments_and_label_values_do_not_become_label_keys(self):
        query = 'requests{route="user_id=123", method="GET"} # bad{request_id="x"}'
        self.assertEqual([name for name, _ in query_labels(query)], ["route", "method"])

    def test_quoted_label_name(self):
        self.write("query.promql", '{"user.id"="42", method="GET"}')
        self.assertEqual([f.label for f in self.scan()[0]], ["user.id"])

    def test_standalone_query_and_exposition(self):
        self.write("query.promql", 'sum by (user_id) (requests_total)')
        self.write("metrics.prom", '# HELP requests_total Requests\nrequests_total{request_id="123"} 1\n')
        self.assertEqual({f.label for f in self.scan()[0]}, {"user_id", "request_id"})

    def test_java_and_kotlin_prometheus_label_declarations(self):
        self.write("Metrics.java", 'Counter.builder().labelNames("method", "userId").register();')
        self.write("Metrics.kt", 'Counter.build().labelNames(\n "request_id", "status"\n).register()')
        self.assertEqual({f.label for f in self.scan()[0]}, {"userId", "request_id"})

    def test_micrometer_keys_not_values(self):
        self.write("Metrics.kt", '''import io.micrometer.core.instrument.Tags
val counter = builder.tags("status", "request_id", "user_id", userId)
val tags = Tags.of("method", "user_id", "requestId", requestId)
''')
        self.assertEqual({f.label for f in self.scan()[0]}, {"user_id", "requestId"})

    def test_micrometer_tag_of(self):
        self.write("Metrics.java", '''import io.micrometer.core.instrument.Tag;
Tag.of("request_id", requestId);
''')
        self.assertEqual([f.label for f in self.scan()[0]], ["request_id"])

    def test_non_monitoring_tag_api_ignored(self):
        self.write("Main.kt", 'thing.tag("user_id", "123")')
        self.assertEqual(self.scan(), ([], 0))

    def test_c_label_arrays_require_constructor_reference(self):
        self.write("metrics.c", '''const char *labels[] = {"method", "user_id"};
const char *other[] = {"request_id"};
prom_counter_new("requests_total", "Requests", 2, labels);
''')
        self.assertEqual([f.label for f in self.scan()[0]], ["user_id"])

    def test_commented_instrumentation_ignored(self):
        self.write("Metrics.java", '// Counter.builder().labelNames("user_id");\n')
        self.write("metrics.c", '''const char *labels[] = {"request_id"};
// prom_counter_new("requests_total", "Requests", 1, labels);
''')
        self.assertEqual(self.scan(), ([], 0))

    def test_c_compound_literal(self):
        self.write("metrics.c", '''prom_counter_new("requests_total", "Requests", 2,
    (const char *[]) {"method", "request_id"});
''')
        self.assertEqual([f.label for f in self.scan()[0]], ["request_id"])

    def test_extra_label_and_directory_exclusions(self):
        self.write("query.promql", 'requests_total{customer_id="42"}')
        self.write("build/generated.promql", 'requests_total{user_id="42"}')
        self.assertEqual(self.cli()[0], 0)
        self.assertEqual(self.cli("--deny-label", "customer_id")[0], 1)
        self.assertEqual(self.cli("--exclude-dir", self.root.name)[0], 0)

    def test_custom_directory_excluded(self):
        self.write("fixtures/query.promql", 'requests_total{user_id="42"}')
        self.assertEqual(self.cli("--exclude-dir", "fixtures")[0], 0)

    def test_invalid_config_fails_instead_of_reporting_skip(self):
        self.write("rules.yaml", 'expr: [unterminated')
        code, output, error = self.cli()
        self.assertEqual(code, 2)
        self.assertIn("unable to complete", error)
        self.assertNotIn("SKIP", output)

    def test_invalid_json_fails(self):
        self.write("dashboard.json", '{"expr": "up",}')
        self.assertEqual(self.cli()[0], 2)

    def test_multiple_yaml_documents_and_recursive_alias(self):
        self.write("rules.yaml", 'a: &a\n  b: *a\n---\nexpr: requests_total{trace_id="123"}\n')
        self.assertEqual([f.label for f in self.scan()[0]], ["trace_id"])

    def test_github_error_annotation(self):
        self.write("monitoring/query.promql", 'requests_total{request_id="123"}')
        with patch.dict(os.environ, {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(self.root)}):
            code, output, _ = self.cli()
        self.assertEqual(code, 1)
        self.assertIn("::error file=monitoring/query.promql,line=1,title=High cardinality::", output)
        self.assertIn("Remove this metric label", output)

    def test_missing_repository_is_scan_error(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main([str(self.root / "missing")]), 2)


if __name__ == "__main__":
    unittest.main()
