from unittest.mock import patch

from webui.app import create_app


def _client():
    return create_app(auth_code='test-auth').test_client()


def _post(client, path, ids):
    return client.post(path, json={'account_ids': ids}, headers={'X-Auth-Code': 'test-auth'})


def test_refresh_expired_at_filters_accounts_and_enqueues_headless_only():
    rows = {
        1: {'id': 1, 'email': 'expired@example.test', 'token_expired': True},
        2: {'id': 2, 'email': 'live@example.test', 'token_expired': False},
        3: {'id': 3, 'email': 'unknown@example.test', 'token_expired': None},
    }
    with patch('webui.app.db.get_account', side_effect=lambda aid: rows.get(aid)), \
         patch('webui.app.live_check_service.enqueue_account_live_checks_batch', return_value=(
             [{'id': 1, 'email': 'expired@example.test'}], [], [],
         )) as enqueue:
        response = _post(_client(), '/api/accounts/refresh-expired-at', [1, 1, 2, 3, 999])
    assert response.status_code == 202
    result = response.get_json()
    assert result['started_count'] == 1
    assert result['skipped_count'] == 3
    assert enqueue.call_args.args[0] == [rows[1]]
    assert enqueue.call_args.kwargs['trigger'] == 'manual_ant_headless_refresh'


def test_refresh_expired_at_does_not_enqueue_valid_at():
    row = {'id': 2, 'email': 'live@example.test', 'token_expired': False}
    with patch('webui.app.db.get_account', return_value=row), \
         patch('webui.app.live_check_service.enqueue_account_live_checks_batch') as enqueue:
        response = _post(_client(), '/api/accounts/refresh-expired-at', [2])
    assert response.status_code == 202
    assert response.get_json()['started_count'] == 0
    enqueue.assert_not_called()


def test_standard_check_live_keeps_manual_trigger():
    row = {'id': 1, 'email': 'expired@example.test', 'token_expired': True}
    with patch('webui.app.db.get_account', return_value=row), \
         patch('webui.app.live_check_service.enqueue_account_live_checks_batch', return_value=([], [], [])) as enqueue:
        response = _post(_client(), '/api/accounts/check-live-bulk', [1])
    assert response.status_code == 202
    assert enqueue.call_args.kwargs['trigger'] == 'manual'
