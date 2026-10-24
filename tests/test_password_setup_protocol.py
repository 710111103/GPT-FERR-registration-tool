from types import SimpleNamespace
from core.password_setup_protocol import classify_auth_state, start_add_password_authorize, follow_add_password_authorize, run_add_password_protocol


def test_classify_states():
    assert classify_auth_state('/email-verification') == 'email_otp'
    assert classify_auth_state('/mfa-challenge') == 'mfa_challenge'
    assert classify_auth_state('', 'First, verify Please enter the current password') == 'current_password_required'
    assert classify_auth_state('/create-account/password') == 'new_password_form'


class Resp:
    def __init__(self, payload=None, url='', text='', status_code=200):
        self.payload, self.url, self.text, self.status_code = payload or {}, url, text, status_code
    def json(self): return self.payload

class FakeSession:
    device_id = 'did-1'
    def __init__(self): self.calls=[]
    def get_nextauth_headers(self, referer=''): return {'referer': referer}
    def get_auth_navigate_headers(self, referer=''): return {'referer': referer}
    def get(self, url, **kwargs):
        self.calls.append(('GET', url, kwargs))
        if url.endswith('/csrf'): return Resp({'csrfToken':'csrf'})
        return Resp({}, url='https://auth.openai.com/email-verification', text='Enter the code')
    def post(self, url, **kwargs):
        self.calls.append(('POST', url, kwargs))
        return Resp({'url':'https://auth.openai.com/authorize?post_login_add_password=true&state=s1'})


def test_authorize_flow_is_independent_from_register():
    s=FakeSession()
    r=start_add_password_authorize(s, 'a@example.com')
    assert r.ok and 'post_login_add_password=true' in r.auth_url
    assert '/api/accounts/user/register' not in s.calls[1][1]
    r=follow_add_password_authorize(s, r)
    assert r.stage == 'email_otp' and r.otp_required


def test_remote_password_is_classified_for_reset():
    s=FakeSession()
    s.get=lambda url, **kwargs: Resp({}, url='https://auth.openai.com/login', text='First, verify Please enter the current password') if not url.endswith('/csrf') else Resp({'csrfToken':'csrf'})
    r=run_add_password_protocol({'email':'a@example.com'}, 'New-pass-123!', session=s)
    assert r.status == 'reset_required' and r.remote_password_present

def test_protocol_endpoint_returns_transaction_state_without_queueing_browser():
    import tempfile, json
    from pathlib import Path
    from unittest.mock import patch
    from core import db
    from webui.app import create_app
    from core.password_setup_protocol import AddPasswordProtocolResult
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); (root/'accounts.json').write_text(json.dumps([{'id':1,'email':'a@example.com'}]), encoding='utf-8')
        patches={'_ACCOUNTS_JSON':root/'accounts.json','_OUTLOOK_JSON':root/'x','_GENERIC_API_EMAIL_JSON':root/'x','_DOMAIN_EMAIL_JSON':root/'x','_JOBS_JSON':root/'x','_LEGACY_ACCOUNTS_JSON':root/'x','_LEGACY_OUTLOOK_JSON':root/'x','_LEGACY_JOBS_JSON':root/'x','_LEGACY_SQLITE':root/'legacy.db','_CODEX_DIR':root/'codex','_CODEX_AGENT_DIR':root/'agents','_LEGACY_CODEX_EXPORT_STATE':root/'x','_SQLITE_READY':False,'_SQLITE_READY_PATH':None,'_VIEWER_HTML':root/'viewer.html','_ACCOUNTS_TXT':root/'accounts.txt','_TOKENS_TXT':root/'tokens.txt'}
        with patch.multiple(db, **patches):
            app=create_app(auth_code='test-auth'); client=app.test_client()
            with patch('core.password_setup_protocol_job.enqueue', return_value={'accepted': True, 'queued': True, 'status': 'queued', 'future': object()}) as enqueue:
                r=client.post('/api/accounts/1/password-setup-protocol',json={'password':'x'},headers={'X-Auth-Code':'test-auth'})
            assert r.status_code==202 and r.get_json()['status']=='queued'
            assert r.get_json()['protocol_only'] is True
            enqueue.assert_called_once_with(1, password='x', reset=False, auto_bridge=True)

def test_password_request_template_replaces_password_without_cookie_headers():
    from core.password_setup_protocol import build_password_request_template, submit_password_request_template, AddPasswordProtocolResult
    class Req:
        method='POST'; url='https://auth.openai.com/api/accounts/password'
        post_data='{"password":"OLD","confirm_password":"OLD"}'
        headers={'content-type':'application/json','cookie':'SECRET'}
        def all_headers(self): return self.headers
    class Resp:
        status_code=200
        def json(self): return {'ok': True}
    class S:
        def request(self, method, url, headers=None, data=None):
            assert 'SECRET' not in headers
            assert 'NEW' in data and 'OLD' not in data
            return Resp()
    t=build_password_request_template(Req())
    r=submit_password_request_template(S(), AddPasswordProtocolResult(True,'x','new_password_form',final_url='https://auth.openai.com/create-account/password'), 'NEW', t)
    assert r['ok'] is True



def test_cloudflare_document_is_resumable_challenge():
    assert classify_auth_state(
        'https://auth.openai.com/api/accounts/authorize',
        '<title>Just a moment...</title><script src="https://challenges.cloudflare.com/x.js"></script>',
        403,
    ) == 'needs_challenge'


def test_protocol_job_public_status_redacts_oauth_urls():
    from core import password_setup_protocol_job as job
    from core.password_setup_protocol import AddPasswordProtocolResult
    result = AddPasswordProtocolResult(
        False, 'needs_challenge', 'needs_challenge', email='a@example.com',
        auth_url='https://auth.openai.com/?state=secret',
        final_url='https://auth.openai.com/challenge?state=secret',
        transaction={'state': 'secret'},
        details={'cf_ray': 'ray-1', 'challenge_url': 'https://auth.openai.com/challenge?state=secret'},
    )
    public = job._public_result(result)
    assert public['auth_url'] == '' and public['final_url'] == '' and public['transaction'] == {}
    assert public['details']['cf_ray'] == 'ray-1'
    assert 'challenge_url' not in public['details']


def test_protocol_challenge_endpoint_queues_cookie_bridge():
    import tempfile, json
    from pathlib import Path
    from unittest.mock import patch
    from core import db
    from webui.app import create_app
    with tempfile.TemporaryDirectory() as td:
        root=Path(td); (root/'accounts.json').write_text(json.dumps([{'id':1,'email':'a@example.com'}]), encoding='utf-8')
        patches={'_ACCOUNTS_JSON':root/'accounts.json','_OUTLOOK_JSON':root/'x','_GENERIC_API_EMAIL_JSON':root/'x','_DOMAIN_EMAIL_JSON':root/'x','_JOBS_JSON':root/'x','_LEGACY_ACCOUNTS_JSON':root/'x','_LEGACY_OUTLOOK_JSON':root/'x','_LEGACY_JOBS_JSON':root/'x','_LEGACY_SQLITE':root/'legacy.db','_CODEX_DIR':root/'codex','_CODEX_AGENT_DIR':root/'agents','_LEGACY_CODEX_EXPORT_STATE':root/'x','_SQLITE_READY':False,'_SQLITE_READY_PATH':None,'_VIEWER_HTML':root/'viewer.html','_ACCOUNTS_TXT':root/'accounts.txt','_TOKENS_TXT':root/'tokens.txt'}
        with patch.multiple(db, **patches):
            app=create_app(auth_code='test-auth'); client=app.test_client()
            queued={'accepted':True,'queued':True,'status':'queued','bridge':True,'future':object()}
            with patch('core.password_setup_protocol_job.bridge_challenge', return_value=queued):
                r=client.post('/api/accounts/1/password-setup-protocol/challenge',headers={'X-Auth-Code':'test-auth'})
            assert r.status_code==202
            assert r.get_json()['bridge'] is True


def test_bridge_challenge_requires_retained_session():
    from core import password_setup_protocol_job as job
    aid=987654321
    with job._LOCK:
        job._PENDING.pop(aid, None); job._RUNNING.discard(aid); job._RESULTS.pop(aid, None)
    r=job.bridge_challenge(aid)
    assert r['missing'] is True and r['status']=='expired'

def test_challenge_bridge_does_not_treat_interstitial_path_as_otp(monkeypatch):
    from core import password_setup_protocol_job as job
    from core.password_setup_protocol import AddPasswordProtocolResult
    import core.browser_environment as browser_environment
    aid = 987654322
    class Session:
        _last_bridge_title = 'しばらくお待ちください...'
        _last_bridge_controls = ['Cloudflare']
        _last_bridge_inputs = []
    session = Session()
    previous = AddPasswordProtocolResult(False, 'needs_challenge', 'needs_challenge', auth_url='https://auth.openai.com/authorize')
    with job._LOCK:
        job._PENDING[aid] = {'session': session, 'result': previous, 'password': 'PLACEHOLDER', 'reset': False, 'updated_at': 1.0}
        job._RUNNING.add(aid)
    monkeypatch.setattr(browser_environment, 'follow_authorize_with_headless_browser', lambda *args, **kwargs: 'https://auth.openai.com/email-verification')
    monkeypatch.setattr(job.db, 'get_account', lambda account_id: {})
    monkeypatch.setattr(job.db, 'update_account_password_setup', lambda *args: True)
    monkeypatch.setattr(job.password_setup_service, '_append_log', lambda *args: None)
    try:
        result = job._bridge_and_resume(aid)
        assert result['status'] == 'needs_challenge'
        assert result['error'] == 'challenge_still_visible'
        assert job._PENDING[aid]['result'].details.get('bridge_landed_stage') is None
        assert aid not in job._RUNNING
    finally:
        with job._LOCK:
            job._PENDING.pop(aid, None)
            job._RESULTS.pop(aid, None)
            job._RUNNING.discard(aid)


def test_completed_result_preserves_transport_metadata_until_login_verification():
    from core import password_setup_protocol_job as job
    from core.password_setup_protocol import AddPasswordProtocolResult

    result = AddPasswordProtocolResult(
        True, "completed", "completed",
        remote_password_present=False,
        response_status=403,
        error="cloudflare_challenge",
    )
    normalized = job._normalize_terminal_result(result)
    public = job._public_result(normalized)

    assert public["ok"] is True
    assert public["status"] == "completed"
    assert public["response_status"] == 403
    assert public["remote_password_present"] is False
    assert public["error"] == "cloudflare_challenge"
    assert public["details"]["terminal_submission_completed"] is True


def test_terminal_submission_does_not_forge_http_or_login_verification():
    from core.password_setup_protocol import AddPasswordProtocolResult
    from core.password_setup_protocol_job import _normalize_terminal_result
    result = AddPasswordProtocolResult(
        True, "completed", "completed", response_status=403, remote_password_present=False,
    )
    _normalize_terminal_result(result)
    assert result.response_status == 403
    assert result.remote_password_present is False
    assert result.details["terminal_submission_completed"] is True


def test_protocol_completed_requires_fresh_login_before_success():
    from unittest.mock import patch
    from core.password_setup_protocol import AddPasswordProtocolResult
    from core import password_setup_protocol_job as job

    class Session:
        def close(self):
            pass

    writes = []
    terminal = AddPasswordProtocolResult(True, "completed", "completed", response_status=200)
    with patch.object(job.db, "get_account", return_value={"id": 1, "email": "a@example.com"}), \
         patch.object(job.db, "update_account_password_setup", side_effect=lambda _aid, value: writes.append(value) or True), \
         patch.object(job, "BrowserSession", return_value=Session()), \
         patch.object(job, "_load_template", return_value=None), \
         patch.object(job, "run_add_password_protocol", return_value=terminal), \
         patch.object(job.password_setup_service, "_verify_password_via_liveness", return_value={"ok": True, "password_accepted": True, "access_token": "new-token", "session": {"user": {"email": "a@example.com"}}}) as verify, \
         patch.object(job.password_setup_service, "_verify_password_login") as browser, \
         patch.object(job.password_setup_service, "_append_log"):
        public = job._run(1, password="candidate-password")
    assert public["status"] == "completed"
    verify.assert_called_once()
    browser.assert_not_called()
    assert public["details"]["verification_method"] == "protocol"
    assert any(item.get("status") == "verifying" and item.get("login_verified") is False for item in writes)
    assert writes[-1]["status"] == "success"
    assert writes[-1]["login_verified"] is True
    assert writes[-1]["password"] == "candidate-password"


def test_protocol_login_rejection_keeps_candidate_hidden():
    from unittest.mock import patch
    from core.password_setup_protocol import AddPasswordProtocolResult
    from core import password_setup_protocol_job as job

    class Session:
        def close(self):
            pass

    writes = []
    terminal = AddPasswordProtocolResult(True, "completed", "completed", response_status=200)
    with patch.object(job.db, "get_account", return_value={"id": 1, "email": "a@example.com"}), \
         patch.object(job.db, "update_account_password_setup", side_effect=lambda _aid, value: writes.append(value) or True), \
         patch.object(job, "BrowserSession", return_value=Session()), \
         patch.object(job, "_load_template", return_value=None), \
         patch.object(job, "run_add_password_protocol", return_value=terminal), \
         patch.object(job.password_setup_service, "_verify_password_via_liveness", side_effect=RuntimeError("incorrect email address or password")), \
         patch.object(job.password_setup_service, "_verify_password_login") as browser, \
         patch.object(job.password_setup_service, "_append_log"):
        public = job._run(1, password="wrong-candidate")
    assert public["ok"] is False
    assert public["status"] == "verification_failed"
    browser.assert_not_called()
    assert writes[-1]["status"] == "verification_failed"
    assert writes[-1]["login_verified"] is False
    assert writes[-1]["candidate_password"] == "wrong-candidate"
    assert "password" not in writes[-1]
