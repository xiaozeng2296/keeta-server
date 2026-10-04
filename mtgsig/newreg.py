"""Keeta push-SDK ``/sdkapi/newreg`` signature recovered from the iOS binary.

The observed inputs are ASCII strings.  The native SHA-1 helper copies a UTF-8
C string using NSString.length, so its behavior for non-ASCII strings is not a
normal UTF-8 hash.  Reject that unverified domain instead of silently claiming
parity for arbitrary Unicode inputs.
"""

import hashlib
from collections.abc import Mapping


# PSEnvironment.appName -> mainBundle.bundleIdentifier.
NEWREG_APP_NAME = "com.sankuai.sailor.ifooddelivery"
# SLHighPriorityLanucher.setupPushService -> SLAppInfo.pushPassword.
NEWREG_PASSWORD = "123456"


def _ascii_text(value, name):
    if not isinstance(value, str):
        raise TypeError(f"newreg {name} must be text")
    if not value.isascii():
        raise ValueError(f"newreg {name} must be ASCII for native parity")
    return value


def newreg_signature(random_value, *, app_name=NEWREG_APP_NAME,
                     password=NEWREG_PASSWORD):
    """Return the lowercase SHA-1 signature for the observed iOS SDK profile.

    The SDK sorts ``app_name``, ``password`` and the request's exact ``random``
    text with NSString ``compare:``, joins with ``-``, and hashes the result.
    ``random_value`` may also be an integer, which is converted to decimal text.
    Text is not stripped or normalized; leading zeros are significant.
    """
    if random_value is None:
        raise ValueError("newreg random is required")
    if isinstance(random_value, int) and not isinstance(random_value, bool):
        random_value = str(random_value)
    values = [
        _ascii_text(app_name, "app_name"),
        _ascii_text(password, "password"),
        _ascii_text(random_value, "random"),
    ]
    material = "-".join(sorted(values)).encode("ascii")
    return hashlib.sha1(material).hexdigest()


def parse_newreg_response(response, *, http_status):
    """Accept the observed top-level pushtoken, not a generic code=0 response.

    Both captured successes have no code field. Optional failure indicators
    must not contradict the token. Keep it opaque and separate from XID/DFP;
    no token is synthesized or read from an alternate/nested field.
    """
    if type(http_status) is not int or not 200 <= http_status < 300:
        return {}
    if not isinstance(response, Mapping):
        return {}
    if any(response.get(field) for field in ("error", "errormsg", "errmsg", "errorMessage", "error_message")):
        return {}
    if "success" in response and response["success"] is not True:
        return {}
    for field in ("code", "errcode", "errorCode"):
        if field in response and not (type(response[field]) is int and response[field] == 0):
            return {}
    token = response.get("pushtoken")
    if not (isinstance(token, str) and token and
            all(char.isprintable() and not char.isspace() for char in token)):
        return {}
    return {"push_token": token}
