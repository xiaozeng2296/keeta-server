"""Pure response-to-workbook mapping; no signing or network access."""
import json,re,time,datetime

SHOP_COLS=["crawl_lat","crawl_lng","user_type","account_name","shop_id","shop_name","shop_status",
 "is_top_shop","shop_categery","distance","shop_eta","delivery_fee","final_delivery_fee","is_keeta_delivery",
 "shop_coupon_name","shop_coupon_entry_threshold","shop_coupon_discount","maximum_discount_amount","shop_coupon_des",
 "del_coupon_name","del_coupon_entry_threshold","del_coupon_discount","del_coupon_des","create_time","timestamp"]


ITEM_COLS=["shop_id","rank","item_category","item_sug_tag","item_id","item_name","item_describe","item_pic",
 "item_discount","item_original_price","item_sale_price","sub_item_json","create_time","timestamp","has_spec",
 "item_discount_price","item_activitytype","item_activityType_json"]


def g(o,*ks,default=None):
    for k in ks:
        if isinstance(o,dict): o=o.get(k)
        elif isinstance(o,list) and isinstance(k,int) and len(o)>k: o=o[k]
        else: return default
        if o is None: return default
    return o


def nums(s):
    return re.findall(r"\d+", s or "")


def now():
    t=datetime.datetime.now()
    return t.strftime("%Y-%m-%d %H:%M:%S"), int(time.time())


def map_shop(d, shop, clat, clng):
    ct,ts=now()
    di=d.get("deliveryInfo") or {}
    ddi=di.get("deliveryDiscountIntroduction") or {}
    # 配送券(del_coupon): 来自 deliveryDiscountIntroduction / activityShowInfo
    del_name=ddi.get("activityShowInfo") or di.get("deliveryDiscountText") or ""
    del_thr=(nums(di.get("deliveryDiscountText") or del_name) or [""])[0]
    dmatch=re.search(r"R\$?\s*(\d+)\s*off", del_name or "", re.I)
    del_disc=dmatch.group(1) if dmatch else (0 if del_name else "")
    del_des=json.dumps([x for x in (g(ddi,"ruleDetails") or [])], ensure_ascii=False) if ddi.get("ruleDetails") else ""
    # 店铺券(shop_coupon): shopActivityList 里"非配送类"活动才算(配送优惠归 del_coupon)。
    # ponytail: 按交付样本(shop_coupon 多为空)best-effort——排除标题含 deliver 的活动;需更多带店铺券的样本核准规则。
    scname=""
    for act in (d.get("shopActivityList") or []):
        title=(act.get("activityTitle") or "")
        if "deliver" not in title.lower():
            scname=act.get("activityShowInfo") or ""; break
    return {
        "crawl_lat":clat,"crawl_lng":clng,"user_type":-1,"account_name":"ph_非登录","shop_id":str(shop),
        "shop_name":d.get("name"),
        "shop_status":g(d,"openingTimeInfo","title",default=""),
        "is_top_shop":"",
        "shop_categery":d.get("primaryCategoryName"),
        "distance":g(d,"distance","number",default=""),
        "shop_eta":"-".join(nums(di.get("deliveryTimeDesc"))[:2]),
        "delivery_fee":g(di,"deliveryFee","amount",default=""),
        "final_delivery_fee":g(d,"finalDeliveryFee","amount",default=0),
        "is_keeta_delivery":di.get("deliveryDesc") or "",
        "shop_coupon_name":scname,"shop_coupon_entry_threshold":"","shop_coupon_discount":"",
        "maximum_discount_amount":"","shop_coupon_des":"",
        "del_coupon_name":del_name,"del_coupon_entry_threshold":del_thr,"del_coupon_discount":del_disc,
        "del_coupon_des":del_des,"create_time":ct,"timestamp":ts,
    }


def specifics_to_subjson(data):
    """productSpecifics.data.skuList[].groupList -> 交付表 sub_item_json 选项组结构"""
    out=[]
    for sku in (data.get("skuList") or []):
        gl=sku.get("groupList") or []
        if not gl: continue
        groups=[]
        for grp in gl:
            groups.append({
                "groupId":grp.get("groupId"),
                "choices_group_name":grp.get("groupName"),
                "choices_group_min":grp.get("minNumber"),
                "choices_group_max":grp.get("maxNumber"),
                "is_required":"Required" if (grp.get("minNumber") or 0)>0 else "Optional",
                "repeatable":grp.get("repeatable") or 0,
                "hasNestedGroup":grp.get("hasNestedGroup") or 0,
                "groupSkuList":[{
                    "groupSkuId":gs.get("groupSkuId"),"spuId":gs.get("spuId"),
                    "sub_item_name":gs.get("name"),
                    "sub_item_price":(gs.get("originPrice") or {}).get("displayText"),
                    "sub_item_tag":(gs.get("extraInfo") or {}).get("logData","") if gs.get("extraInfo") else "",
                } for gs in (grp.get("groupSkuList") or [])]
            })
        if groups: out.append({"skuId":sku.get("skuId"),"groupList":groups})
    return out


def spu_to_row(spu, cname, rank, shop, ct, ts, sub=""):
    tag=g(spu,"promotionTagInfo","discountTag","text",default="") or g(spu,"productTagInfo","recommendTagForWindow","text",default="")
    acts=spu.get("activityInfoList") or []
    sale_price=g(spu,"discountPrice","amount",default=None)
    if sale_price is None: sale_price=g(spu,"minPrice","amount",default="")
    return {
        "shop_id":str(shop),"rank":rank,"item_category":cname,"item_sug_tag":tag,
        "item_id":spu.get("spuId"),"item_name":spu.get("name"),
        "item_describe":spu.get("description") or "",
        "item_pic":(spu.get("pictures") or [""])[0],
        "item_discount":tag,
        "item_original_price":g(spu,"minPrice","amount",default=""),
        "item_sale_price":sale_price,
        "sub_item_json":sub,"create_time":ct,"timestamp":ts,
        "has_spec":spu.get("haveMultiSpecs") or 0,
        "item_discount_price":sale_price,
        "item_activitytype":g(acts,0,"activityType",default=""),
        "item_activityType_json":json.dumps(acts,ensure_ascii=False) if acts else "",
    }


def map_items(d, shop, details=None):
    """把已保存的菜单和定制结果映射成表格；缺失项保留 ID，由覆盖报告判定完整度。"""
    ct,ts=now(); rows=[]; rank=0
    for cat in (d.get("shopCategoryList") or []):
        cname=cat.get("shopCategoryName")
        inline={spu.get("spuId"):spu for spu in (cat.get("spuList") or [])}
        ids=cat.get("spuIdList") or list(inline.keys())
        if not ids: ids=list(inline.keys())
        for spuId in ids:
            rank+=1; spu=inline.get(spuId); sub=""
            saved = (details or {}).get(str(spuId))
            if isinstance(saved, dict) and saved.get("code") == 0 and saved.get("data"):
                spu = dict(spu or {}, **saved["data"])
                groups = specifics_to_subjson(saved["data"])
                sub = json.dumps(groups, ensure_ascii=False) if groups else ""
            if spu is None:  # 详情也没取到, 至少留 id
                rows.append({"shop_id":str(shop),"rank":rank,"item_category":cname,"item_id":spuId,
                             "item_name":"","item_describe":"","item_pic":"","item_sug_tag":"","item_discount":"",
                             "item_original_price":"","item_sale_price":"","sub_item_json":"","create_time":ct,
                             "timestamp":ts,"has_spec":"","item_discount_price":"","item_activitytype":"","item_activityType_json":""})
                continue
            rows.append(spu_to_row(spu, cname, rank, shop, ct, ts, sub))
    return rows
