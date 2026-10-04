"""读 数据采集任务.xlsx -> [ShopTask]，并把任务确定性分片到账号。"""
import openpyxl
import math


class ShopTask:
    __slots__ = ("shop_id", "lat", "lng", "city", "name")

    def __init__(self, shop_id, lat, lng, city="", name=""):
        self.shop_id = str(shop_id)
        self.lat = str(lat)
        self.lng = str(lng)
        self.city = city
        self.name = name

    def __repr__(self):
        return f"ShopTask({self.shop_id}, {self.lat}, {self.lng})"


def _isnum(x):
    try:
        float(x)
        return True
    except (TypeError, ValueError):
        return False


def load_tasks(xlsx_path, strict=False):
    """读第一个 sheet；跳过 shop_id 空或坐标非数字的脏行。"""
    wb = openpyxl.load_workbook(xlsx_path, read_only=True, data_only=True)
    ws = wb.worksheets[0]
    it = ws.iter_rows(values_only=True)
    hdr = [str(c).strip() if c is not None else "" for c in next(it, ())]
    idx = {h: i for i, h in enumerate(hdr)}
    if "shop_id" not in idx:
        wb.close()
        raise ValueError(f"任务表缺 shop_id 列，实有: {hdr}")

    def cell(row, name):
        i = idx.get(name)
        return row[i] if i is not None and i < len(row) else None

    out = []
    for line, r in enumerate(it, 2):
        if not any(x is not None for x in r):
            continue
        sid = cell(r, "shop_id")
        lat = cell(r, "crawl_lat")
        lng = cell(r, "crawl_lng")
        if sid is None or not _isnum(lat) or not _isnum(lng):
            if strict:
                wb.close()
                raise ValueError(f'第 {line} 行店铺 ID 或坐标缺失')
            continue
        sid = str(int(sid)) if isinstance(sid, float) else str(sid)
        if strict and (not sid.isascii() or not sid.isdigit() or int(sid) <= 0 or
                       len(sid) > 40 or not math.isfinite(float(lat)) or not -90 <= float(lat) <= 90 or
                       not math.isfinite(float(lng)) or not -180 <= float(lng) <= 180):
            wb.close()
            raise ValueError(f'第 {line} 行店铺 ID 或坐标无效')
        city = str(cell(r, 'city_id') or '102302389') if strict else str(cell(r, 'city') or '')
        if strict and (not city.isascii() or not city.isdigit() or len(city)>40):
            wb.close()
            raise ValueError(f'第 {line} 行 city_id 无效')
        out.append(ShopTask(sid, lat, lng,
                            city,
                            str(cell(r, "shop_name") or "")))
    wb.close()
    if strict and not out:
        raise ValueError('任务表没有有效店铺')
    return out
