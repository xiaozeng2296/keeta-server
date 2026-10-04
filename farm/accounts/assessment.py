"""Validate passport identity responses against the selected account."""
def assess_response(http_status, response, expected_user_id):
    """HTTP 200 不代表有效账号；成功响应须包含同一账号的 user.idStr。"""
    result = {"valid": False, "http_status": http_status}
    if http_status != 200:
        return dict(result, reason="http_error")
    if not isinstance(response, dict):
        return dict(result, reason="non_json_object")
    if response.get("error") or ("code" in response and response["code"] != 0):
        return dict(result, reason="business_error")
    user = response.get("user")
    if not isinstance(user, dict):
        return dict(result, reason="missing_user")
    user_id = user.get("idStr")
    if not isinstance(user_id, str) or not user_id.isascii() or not user_id.isdigit() or int(user_id) <= 0:
        return dict(result, reason="missing_user_id")
    if "id" in user and (type(user["id"]) is not int or str(user["id"]) != user_id):
        return dict(result, reason="inconsistent_user_id")
    if not expected_user_id:
        return dict(result, reason="missing_expected_user_id")
    if user_id != str(expected_user_id):
        return dict(result, reason="account_mismatch")
    return dict(result, valid=True, reason="verified", user_id=user_id)
