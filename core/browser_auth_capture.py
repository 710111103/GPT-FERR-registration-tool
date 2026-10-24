"""Allowlisted Chromium CDP authentication metadata, never raw HAR/secrets."""
import json
from urllib.parse import urlsplit, parse_qs

PATHS = {
    '/auth/login', '/api/auth/providers', '/api/auth/csrf',
    '/api/auth/signin/openai', '/api/accounts/authorize',
    '/api/accounts/password/verify', '/api/accounts/mfa/verify',
    '/api/auth/callback/openai', '/api/auth/session',
    '/api/accounts/authorize/continue', '/api/accounts/email-otp/validate',
    '/api/accounts/email-otp/send',
}
KEYS = {'accessToken','user','account','expires','email','id','name','planType',
        'url','continue_url','redirect_url','page','type','error','code','message',
        'csrfToken','success','status','mfa_required','factors','methods'}
QUERY_KEYS = {'code','state','error','redirect_uri','client_id','scope','response_type','nonce'}

def endpoint(url):
    parsed = urlsplit(str(url))
    if parsed.hostname not in ('chatgpt.com','auth.openai.com') or parsed.path not in PATHS:
        return None
    return {'host': parsed.hostname, 'path': parsed.path,
            'query_keys': sorted(set(parse_qs(parsed.query, keep_blank_values=True)) & QUERY_KEYS)}

def shape(value, depth=0):
    if depth > 3: return 'nested'
    if isinstance(value,dict):
        return {key: shape(val,depth+1) for key,val in value.items() if key in KEYS}
    if isinstance(value,list): return {'type':'array','sample':shape(value[0],depth+1) if value else None}
    if value is None: return 'null'
    if isinstance(value,bool): return 'boolean'
    if isinstance(value,(int,float)): return 'number'
    return 'string'

class BrowserAuthCapture:
    def __init__(self, page, emit):
        self.emit = emit
        self.pending = {}
        self.last_status = {}
        self.cdp = page.context.new_cdp_session(page)
        self.cdp.send('Network.enable')
        self.cdp.on('Network.requestWillBeSent', self.request)
        self.cdp.on('Network.responseReceived', self.response)
        self.cdp.on('Network.loadingFinished', self.finished)
        self.cdp.on('Network.loadingFailed', self.failed)

    def request(self, event):
        request = event.get('request',{})
        # Redirect responses belong to the previous URL, even when the new
        # destination is outside the capture allowlist (e.g. the home page).
        redir = event.get('redirectResponse')
        if redir:
            previous = endpoint(redir.get('url',''))
            if previous:
                status = int(redir.get('status',0))
                self.last_status[previous['path']] = status
                self.emit('cdp_redirect',status=status,**previous)
        target = endpoint(request.get('url',''))
        if not target:
            self.pending.pop(event.get('requestId'),None)
            return
        self.pending[event['requestId']] = target
        record = dict(target,method=request.get('method'))
        data = request.get('postData','')
        if data and len(data)<65536:
            try: record['body_shape']=shape(json.loads(data))
            except (ValueError,TypeError): record['body_shape']='non_json'
        self.emit('cdp_request', **record)

    def response(self, event):
        response=event.get('response',{})
        target=endpoint(response.get('url',''))
        if not target: return
        status=int(response.get('status',0))
        self.last_status[target['path']]=status
        self.pending[event['requestId']]=dict(target,json_response='json' in response.get('mimeType',''))
        self.emit('cdp_response',status=status,**target)

    def finished(self,event):
        target=self.pending.pop(event.get('requestId'),None)
        if not target or not target.pop('json_response',False): return
        if event.get('encodedDataLength',0)>65536: return
        try:
            body=self.cdp.send('Network.getResponseBody',{'requestId':event['requestId']})
            if body.get('base64Encoded') or len(body.get('body',''))>65536: return
            data=json.loads(body.get('body',''))
            record=dict(target,response_shape=shape(data))
            if target['path']=='/api/auth/session' and isinstance(data,dict):
                record['token_present']=bool(data.get('accessToken'))
            self.emit('cdp_response_shape',**record)
        except Exception:
            self.emit('cdp_body_unavailable',**target)

    def failed(self,event):
        target=self.pending.pop(event.get('requestId'),None)
        if target:
            target.pop('json_response',None)
            self.emit('cdp_request_failed',**target)
