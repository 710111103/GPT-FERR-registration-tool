from core.browser_auth_capture import endpoint, shape, BrowserAuthCapture
from unittest.mock import Mock

def test_endpoint_never_records_query_values_or_arbitrary_paths():
    value=endpoint('https://chatgpt.com/api/auth/callback/openai?code=SECRET&state=PRIVATE&email=hidden')
    assert value['query_keys']==['code','state']
    assert 'SECRET' not in str(value) and 'PRIVATE' not in str(value)
    assert endpoint('https://chatgpt.com/arbitrary/user-secret') is None
    assert endpoint('https://other.example/api/auth/session') is None

def test_shapes_never_record_secrets_or_unknown_keys():
    value=shape({'accessToken':'SECRET','user':{'email':'PRIVATE'},'password':'HIDDEN','code':'OTP'})
    assert value=={'accessToken':'string','user':{'email':'string'},'code':'string'}

def test_cdp_records_empty_and_authenticated_session_shapes():
    page=Mock(); emit=Mock(); capture=BrowserAuthCapture(page,emit)
    capture.response({'requestId':'1','response':{'url':'https://chatgpt.com/api/auth/session','status':200,'mimeType':'application/json'}})
    capture.cdp.send.return_value={'body':'{}','base64Encoded':False}
    capture.finished({'requestId':'1','encodedDataLength':2})
    assert emit.call_args.kwargs['token_present'] is False
    capture.response({'requestId':'2','response':{'url':'https://chatgpt.com/api/auth/session','status':200,'mimeType':'application/json'}})
    capture.cdp.send.return_value={'body':'{"accessToken":"SECRET"}'}
    capture.finished({'requestId':'2','encodedDataLength':40})
    assert emit.call_args.kwargs['token_present'] is True
    assert 'SECRET' not in str(emit.call_args_list)


def test_callback_redirect_to_home_is_recorded_without_destination_secrets():
    page=Mock(); emit=Mock(); capture=BrowserAuthCapture(page,emit)
    capture.pending['r']={'path':'/api/auth/callback/openai'}
    capture.request({
        'requestId':'r',
        'request':{'url':'https://chatgpt.com/?private=SECRET','method':'GET'},
        'redirectResponse':{
            'url':'https://chatgpt.com/api/auth/callback/openai?code=SECRET',
            'status':302,
        },
    })
    assert emit.call_count == 1
    assert emit.call_args.args == ('cdp_redirect',)
    assert emit.call_args.kwargs['status'] == 302
    assert capture.last_status['/api/auth/callback/openai'] == 302
    assert 'r' not in capture.pending
    assert 'SECRET' not in str(emit.call_args_list)


def test_redirect_between_allowed_urls_emits_redirect_once_before_request():
    page=Mock(); emit=Mock(); capture=BrowserAuthCapture(page,emit)
    capture.request({
        'requestId':'r',
        'request':{'url':'https://chatgpt.com/api/auth/session','method':'GET'},
        'redirectResponse':{'url':'https://chatgpt.com/auth/login','status':307},
    })
    assert [call.args[0] for call in emit.call_args_list] == ['cdp_redirect','cdp_request']
    assert capture.pending['r']['path'] == '/api/auth/session'
