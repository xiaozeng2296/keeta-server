"""Minimal identity metadata for the panel; never copy tokens or raw user profiles."""
from datetime import datetime, timezone
import fcntl
import json
from pathlib import Path
import tempfile
import os

from farm.mysql_store import ROOT, when
from tools.check_account import assess_response

PROFILE_ROOT=ROOT/'.private/account-profiles'
FIELDS=('account_id','session_id','user_id','email','username','verified_at')


def read_profile(aid):
    path=PROFILE_ROOT/(str(int(aid))+'.json')
    if not path.is_file() or path.is_symlink():return None
    try:
        value=json.loads(path.read_text())
        return {k:value.get(k) for k in FIELDS} if isinstance(value,dict) and value.get('account_id')==int(aid) else None
    except (OSError,ValueError,TypeError):return None


def remember_profile(aid,sid,user_id,response,at=None):
    if not isinstance(response,dict) or not assess_response(response.get('_http_status',200),response,user_id)['valid']:
        raise ValueError('account profile identity mismatch')
    user=response['user'];email=user.get('email');username=user.get('username')
    if not isinstance(email,str) or len(email)>320 or '@' not in email or any(c.isspace() for c in email):email=None
    if not isinstance(username,str):username=None
    record=dict(account_id=int(aid),session_id=int(sid),user_id=str(user_id),email=email,
                username=username[:200] if username else None,verified_at=at or datetime.now(timezone.utc).isoformat())
    PROFILE_ROOT.mkdir(mode=0o700,parents=True,exist_ok=True)
    with (PROFILE_ROOT/(str(int(aid))+'.lock')).open('a') as guard:
        fcntl.flock(guard,fcntl.LOCK_EX)
        old=read_profile(aid)
        if old and old['user_id']==record['user_id']:
            if old['verified_at'] and when(old['verified_at'])>when(record['verified_at']):return old
            if not record['email']:record['email']=old.get('email')
        fd,stage=tempfile.mkstemp(prefix='profile-',dir=PROFILE_ROOT)
        try:
            with os.fdopen(fd,'w') as stream:json.dump(record,stream,ensure_ascii=False)
            os.replace(stage,PROFILE_ROOT/(str(int(aid))+'.json'))
        finally:
            if os.path.exists(stage):os.unlink(stage)
    return record


def overlay_profiles(accounts):
    for account in accounts:
        profile=read_profile(account['id'])
        if not profile or profile['user_id']!=str(account.get('user_id')):continue
        account['email']=profile['email'];account['username']=profile['username']
        if profile['session_id']==account.get('active_session_id'):
            account['identity_verified_at']=profile['verified_at']
    return accounts
