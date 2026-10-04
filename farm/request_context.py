"""Build requests from one account's saved curl, without shared capture credentials."""
from copy import deepcopy
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit


class RequestContext:
    def __init__(self, root):
        if isinstance(root, dict):
            self.base = deepcopy(root["request"])
            self.templates = deepcopy(root["templates"])
            self.identity = deepcopy(root["identity"])
        else:
            root = Path(root)
            self.base = json.loads((root / "request.json").read_text(encoding="utf-8"))
            self.templates = json.loads((root / "endpoint_templates.json").read_text(encoding="utf-8"))
            self.identity = json.loads((root / "identity.json").read_text(encoding="utf-8"))
        self.origin = urlsplit(self.base["url"])
        if self.origin.scheme != "https" or self.origin.username or self.origin.password:
            raise ValueError("invalid captured request origin")

    def _prepare(self, path):
        template = self.templates[path]
        url = template["url"]
        parsed = urlsplit(url)
        if (parsed.scheme, parsed.netloc) != (self.origin.scheme, self.origin.netloc) or parsed.path != path:
            raise ValueError("endpoint template does not match this account's captured origin/path")
        if template.get("method", "POST") != "POST":
            raise ValueError("shop templates require POST")
        # Charles HTTP/2 exports include pseudo-headers; URL/method already
        # represent them. They are not legal requests/HTTP1 header names.
        headers = {k.lower(): v for k, v in template.get("headers", self.base["headers"]).items()
                   if not k.startswith(":")}
        for key in ("token", "uuid", "userid", "csecuuid", "csecuserid"):
            if self.identity.get(key) and headers.get(key) != self.identity[key]:
                raise ValueError("request template identity mismatch: " + key)
        query = parse_qs(parsed.query)
        for key in ("uuid", "userid"):
            if key in query and query[key] != [self.identity.get(key)]:
                raise ValueError("request query identity mismatch: " + key)
        for key in ("mtgsig", "content-length", "accept-encoding"):
            headers.pop(key, None)
        headers["host"] = parsed.netloc
        body = deepcopy(template["body"])
        if isinstance(body, str):
            body = json.loads(body)
        return url, headers, body

    def build_shop_list(self, page):
        if type(page) is not int or page < 0:
            raise ValueError("shop list page must be a nonnegative integer")
        url, headers, body = self._prepare("/api/v4/homePage/homeShopList")
        body["pageNo"] = page
        return url, headers, json.dumps(body, ensure_ascii=False, separators=(",", ":"))

    def build(self, path, shop, lat, lng, *, city=None, spu_id=None):
        url, headers, body = self._prepare(path)
        if city is not None:
            url = re.sub(r"([?&]ci=)[^&]*", lambda m: m[1] + str(city), url)
            headers["cityid"] = str(city)
        body["shopId"] = str(shop)
        if isinstance(body.get("location"), dict):
            body["location"].update(latitude=str(lat), longitude=str(lng))
        if "latitude" in body:
            body["latitude"] = str(lat)
        if "longitude" in body:
            body["longitude"] = str(lng)
        if spu_id is not None:
            body["spuId"] = spu_id
        return url, headers, json.dumps(body, ensure_ascii=False, separators=(",", ":"))
