# SPDX-License-Identifier: Apache-2.0
"""Exercise public alert-template checks without deploying notification services."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parent.parent / 'alert_check.py'
spec = importlib.util.spec_from_file_location('public_alert_check', SCRIPT)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class PublicAlertTests(unittest.TestCase):
    def setUp(self):
        self.rules = a.RULES.read_text()
        self.manager = a.ALERTMANAGER.read_text()
        self.prometheus = a.PROMETHEUS.read_text()
        self.procedure = a.testfire_section(a.TESTFIRE_RUNBOOK.read_text())
        self.alerts = a.parse_rules(self.rules)
        self.am = a.parse_alertmanager(self.manager)

    def problems(self, **changes):
        args = dict(alerts=self.alerts, am=self.am, prometheus_text=self.prometheus, testfire_md=self.procedure)
        args.update(changes)
        return a.notify_noise_problems(**args)

    def test_current_public_inputs_pass_without_private_compose(self):
        self.assertFalse((a.ROOT / 'deploy/docker-compose.prod.yml').exists())
        self.assertEqual(self.problems(), [])
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(a.main(), 0)
        self.assertIn('installed monitoring and notification delivery are not tested', out.getvalue())
        self.assertEqual(len(self.alerts), 29)

    def test_missing_prometheus_rule_and_alertmanager_wiring_rejected(self):
        for old, new, error in [('alert-rules.yml', 'absent.yml', 'rule_files'),
                                ('alertmanager:9093', 'missing:9093', 'target')]:
            with self.subTest(old=old):
                self.assertTrue(any(error in p for p in self.problems(prometheus_text=self.prometheus.replace(old, new))))

    def test_operator_rendering_instructions_are_required(self):
        for old in ['__ALERT_WEBHOOK_URL__', '__ALERT_TG_BOT_TOKEN__', '__ALERT_TG_CHAT_ID__',
                    'amtool check-config', 'YAML integer', 'does not expand']:
            with self.subTest(old=old):
                self.assertTrue(any('rendering:' in p for p in self.problems(testfire_md=self.procedure.replace(old, 'removed'))))

    def test_unexpected_or_missing_template_variable_rejected(self):
        for manager in [self.manager.replace('__ALERT_TG_CHAT_ID__', '0'),
                        self.manager + '\n# __NEW_REQUIRED_SECRET__\n']:
            self.assertTrue(any('rendering:' in p for p in self.problems(am=a.parse_alertmanager(manager))))

    def test_receivers_and_critical_fanout_cannot_disappear(self):
        for field, replacement in [('receivers', ['webhook']), ('children', [])]:
            changed = copy.deepcopy(self.am)
            changed[field] = replacement
            self.assertTrue(self.problems(am=changed))

    def test_critical_channel_cannot_be_silently_dropped(self):
        changed = copy.deepcopy(self.am)
        changed['receiver_kinds']['critical'].remove('telegram')
        self.assertTrue(any('fan-out' in p for p in self.problems(am=changed)))

    def test_severity_and_persistence_are_required(self):
        for field in ['severity', 'for']:
            changed = copy.deepcopy(self.alerts)
            target = next(x for x in changed if 'absent(' not in x['expr'])
            target['annotations'].pop(field, None)
            self.assertTrue(any('missing ' + field in p for p in self.problems(alerts=changed)))

    def test_invalid_or_noisy_timing_rejected(self):
        for key, value in [('group_wait', 'nonsense'), ('group_interval', '0s'), ('repeat_interval', '1m')]:
            changed = copy.deepcopy(self.am)
            changed['timings'][key] = value
            self.assertTrue(self.problems(am=changed))

    def test_inhibition_and_critical_test_fire_remain_required(self):
        changed = copy.deepcopy(self.am)
        changed['inhibit_equal_alertname'] = False
        self.assertTrue(any('inhibit' in p for p in self.problems(am=changed)))
        self.assertTrue(any('critical-severity' in p for p in self.problems(testfire_md=self.procedure.replace('"severity": "critical"', '"severity": "info"'))))

    def test_rule_metric_and_exact_runbook_document_are_checked(self):
        for text, error in [
            (self.rules.replace('gateway_http_requests_total', 'gateway_not_declared_total'), 'not declared'),
            (self.rules.replace('docs/runbooks/alerts.md#', 'docs/runbooks/nonexistent.md#'), 'anchor'),
            (self.rules.replace('#ServiceDown', '#Service'), 'anchor'),
        ]:
            with tempfile.TemporaryDirectory() as directory:
                rules = Path(directory) / 'rules.yml'
                rules.write_text(text)
                out = io.StringIO()
                with patch.object(a, 'RULES', rules), contextlib.redirect_stdout(out):
                    self.assertEqual(a.main(), 1)
                self.assertIn(error, out.getvalue())

    def test_multiline_expression_is_not_ignored(self):
        alerts = a.parse_rules('- alert: Example\n  expr: |\n    sum(rate(gateway_example_total[5m])) > 0\n  for: 1m\n')
        self.assertEqual(a.expr_metrics(alerts[0]['expr']), {'gateway_example_total'})


if __name__ == '__main__':
    unittest.main()
