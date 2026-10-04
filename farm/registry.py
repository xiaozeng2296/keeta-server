'读 accounts.json -> [AccountEnv]。\n\naccounts.json 形如:\n{\n  "acct_546": {"device": "192.168.5.46:27042", "proxy": "socks5h://${PROXY_USERNAME}:${PROXY_PASSWORD}@ip:port",\n               "front_proxy": "http://127.0.0.1:7897", "ci": "102302389"}\n}\nidentity/sample 路径由 env 从 workspace/<acct>/ 推导，不写进注册表。\n'
import json
from pathlib import Path



def account_proxy(account_dir, accounts_json=None):
    """Use the same per-account route for curl validation and collection."""
    config = Path(accounts_json) if accounts_json else Path(__file__).resolve().parents[1] / 'accounts.json'
    if not config.exists():
        return None
    registry = json.loads(config.read_text(encoding='utf-8'))
    return (registry.get(Path(account_dir).name) or {}).get('proxy')


def account_front_proxy(account_dir, accounts_json=None):
    """Return the optional loopback proxy used before the account exit."""
    config = Path(accounts_json) if accounts_json else Path(__file__).resolve().parents[1] / 'accounts.json'
    if not config.exists():
        return None
    registry = json.loads(config.read_text(encoding='utf-8'))
    return (registry.get(Path(account_dir).name) or {}).get('front_proxy')


def curl_proxy_args(proxy):
    # An ambient NO_PROXY must not silently bypass an explicitly selected route.
    return ['--proxy', proxy, '--noproxy', ''] if proxy else []


def load_registry(accounts_json, workspace_root=None):
    if workspace_root is None:
        raise ValueError("目录式账号入口已停用，请使用 farm.mysql_cli")
    from farm.env import AccountEnv
    data = json.loads(Path(accounts_json).read_text(encoding="utf-8"))
    envs = []
    for acct_id, cfg in data.items():
        cfg = cfg or {}
        envs.append(AccountEnv(acct_id, workspace_root,
                               device=cfg.get("device"),
                               proxy=cfg.get("proxy"),
                               front_proxy=cfg.get("front_proxy"),
                               ci=cfg.get("ci")))
    return envs
