import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from core import db
from webui.app import create_app


class BulkSecretSpeedTests(unittest.TestCase):
    def test_a_bulk_lookup_matches_single_and_skips_full_table_loader(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            accounts = root / 'accounts.json'
            accounts.write_text(json.dumps([
                {'id': i, 'email': f'user{i}@example.test', 'access_token': f'token-{i}' if i % 2 else ''}
                for i in range(1, 820)
            ]), encoding='utf-8')
            missing = root / 'missing.json'
            with patch.multiple(db, _ACCOUNTS_JSON=accounts, _LEGACY_ACCOUNTS_JSON=missing,
                                _OUTLOOK_JSON=missing, _GENERIC_API_EMAIL_JSON=missing,
                                _JOBS_JSON=missing, _DOMAIN_EMAIL_JSON=missing), \
                 patch.object(db, '_SQLITE_READY', False), patch.object(db, '_SQLITE_READY_PATH', None):
                expected = {i: db.get_account(i) for i in (1, 2, 400, 401, 819)}
                with patch.object(db, '_load_accounts', side_effect=AssertionError('full scan')):
                    actual = db.get_accounts_by_ids([1, 2, 400, 401, 819, 1, 900])
                    self.assertEqual(set(actual), set(expected))
                    for key in expected:
                        self.assertEqual(actual[key]['access_token'], expected[key]['access_token'])
                    self.assertEqual(len(db.get_accounts_by_ids(list(range(1, 820)))), 819)

    def test_bulk_endpoint_keeps_order_and_skipped_reasons(self):
        recoveries = {name: (lambda: 0) for name in (
            'recover_interrupted_plan_checks', 'recover_interrupted_extract_links',
            'recover_interrupted_live_checks', 'recover_interrupted_payment_checks',
            'recover_interrupted_codex_agents', 'recover_interrupted_totp_setups',
            'recover_interrupted_totp_rotations', 'recover_interrupted_email_changes')}
        with patch('webui.app.plan_check_service.start_account_status_scheduler'), \
             patch('webui.app.svc.cleanup_stale_jobs_on_init'), patch.multiple(db, **recoveries):
            app = create_app(auth_code='bulk-test')
        client = app.test_client()
        client.post('/login', data={'auth_code': 'bulk-test', 'next': '/'})
        accounts = {2: {'id': 2, 'email': 'b@example.test', 'access_token': 'b-token'},
                    1: {'id': 1, 'email': 'a@example.test', 'access_token': ''}}
        with patch('webui.app.db.get_accounts_by_ids', return_value=accounts) as lookup, \
             patch('webui.app.db.get_account', side_effect=AssertionError('per-account read')):
            response = client.post('/api/accounts/secret-bulk', json={
                'account_ids': [2, 'bad', 1, 2, 999], 'field': 'access_token'})
        self.assertEqual(response.status_code, 200)
        result = response.get_json()
        self.assertEqual([v['value'] for v in result['values']], ['b-token'])
        self.assertEqual([s['reason'] for s in result['skipped']], ['ID 非法', '值为空', '账号不存在'])
        lookup.assert_called_once_with([2, 1, 2, 999])


if __name__ == '__main__':
    unittest.main()



