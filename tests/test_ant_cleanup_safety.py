from unittest.mock import patch
from core import antbrowser_driver as d

BASE='http://127.0.0.1:19876'

def run_cleanup(profile, status=None):
    def api(method,url,**kwargs):
        if url.endswith('/api/profiles'): return {'items':[profile]}
        if url.endswith('/status'): return status or {}
        return {}
    with patch.object(d,'_ant_json',side_effect=api) as api_mock, patch.object(d.time,'time',return_value=200000), patch.object(d.time,'sleep'):
        d._cleanup_stale_ant_profiles(BASE)
    return [(c.args[0],c.args[1]) for c in api_mock.call_args_list]

def test_old_running_profile_is_never_stopped_by_sweeper():
    calls=run_cleanup({'profileId':'active','profileName':'TurbGPT-100000','running':True})
    assert all(method=='GET' for method,url in calls)

def test_new_unstarted_profile_is_not_deleted():
    calls=run_cleanup({'profileId':'starting','profileName':'TurbGPT-199999','running':False})
    assert all(method=='GET' for method,url in calls)

def test_old_stopped_profile_requires_status_confirmation():
    calls=run_cleanup({'profileId':'stale','profileName':'TurbGPT-100000','running':False}, {'running':True})
    assert all(method=='GET' for method,url in calls)

def test_old_stopped_confirmed_profile_can_be_deleted():
    calls=run_cleanup({'profileId':'stale','profileName':'TurbGPT-100000','running':False})
    assert ('GET', BASE+'/api/profiles/stale/status') in calls
    assert ('DELETE',BASE+'/api/profiles/stale') in calls

def test_unknown_age_profile_is_preserved():
    calls=run_cleanup({'profileId':'unknown','profileName':'TurbGPT-unknown','running':False})
    assert all(method=='GET' for method,url in calls)
