// Keeta 设备端 mtgsig 签名 RPC。
// 思路(参考国内 mtgsig_app 的 sign_multi.py):不离线复现算法,直接调 Keeta 自己的
// 签名器 +[SAKRequestSignatureProcessor signaturedWithMutableURLRequest:],签完从 request 读回 mtgsig。
// 用法:frida 连上 Keeta 后 load 本脚本,Python 侧 script.exports_sync.sign(method,url,body)。
'use strict';

function str(s) {
    return ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(s));
}

// 找签名器类:优先 SAKRequestSignatureProcessor,否则按名字扫。
function findSigner() {
    var C = ObjC.classes;
    if (C.SAKRequestSignatureProcessor) return 'SAKRequestSignatureProcessor';
    for (var n in C) {
        if (/SAK.*Signature.*Processor|Signature.*Processor|MTGuard/i.test(n)) return n;
    }
    return null;
}

// 找签名方法名:含 signatur 且吃一个 request 参数的类/实例方法。
function findSignSel(cls) {
    var c = ObjC.classes[cls];
    var pool = c.$ownMethods.concat(c.$methods);
    for (var i = 0; i < pool.length; i++) {
        var m = pool[i];
        if (/signatur/i.test(m) && /request|url/i.test(m)) return m;
    }
    return null;
}

function buildReq(method, url, body) {
    var C = ObjC.classes;
    var req = C.NSMutableURLRequest.requestWithURL_(C.NSURL.URLWithString_(str(url)));
    req.setHTTPMethod_(str(method || 'POST'));
    if (body && body.length) {
        req.setHTTPBody_(str(body).dataUsingEncoding_(4)); // NSUTF8StringEncoding
    }
    return req;
}

function readMtgsig(req) {
    var h = req.allHTTPHeaderFields();
    if (h) {
        var v = h.objectForKey_('mtgsig');
        if (v) return v.toString();
    }
    return null;
}

var SIGNER = null, SEL = null;

rpc.exports = {
    // 诊断:在真机上确认类/方法是否如预期
    classes: function () {
        var C = ObjC.classes, hits = [];
        for (var n in C) {
            if (/SAK.*Signature|Signature.*Processor|MTGuard|MTGSig|SAKGuard/i.test(n)) hits.push(n);
        }
        var sel = null, own = null;
        var s = findSigner();
        if (s) { try { own = ObjC.classes[s].$ownMethods; } catch (e) {} sel = findSignSel(s); }
        return { candidates: hits, signer: s, signSel: sel, ownMethods: own };
    },

    // 核心:对任意请求签名,返回 mtgsig 字符串
    sign: function (method, url, body) {
        if (!SIGNER) { SIGNER = findSigner(); if (SIGNER) SEL = findSignSel(SIGNER); }
        if (!SIGNER) return { err: 'signer class not found' };
        var C = ObjC.classes;
        var req = buildReq(method, url, body);
        try {
            // 已知入口是类方法 +signaturedWithMutableURLRequest:
            if (typeof C[SIGNER].signaturedWithMutableURLRequest_ === 'function') {
                C[SIGNER].signaturedWithMutableURLRequest_(req);
            } else if (SEL) {
                // 回退:按扫描到的 selector 调(类方法优先,再实例)
                var jsSel = SEL.replace(/^[-+]\s*/, '').replace(/:/g, '_');
                if (typeof C[SIGNER][jsSel] === 'function') {
                    C[SIGNER][jsSel](req);
                } else {
                    var inst = C[SIGNER].sharedInstance ? C[SIGNER].sharedInstance()
                             : C[SIGNER].alloc().init();
                    inst[jsSel](req);
                }
            } else {
                return { err: 'sign selector not found', signer: SIGNER };
            }
        } catch (e) {
            return { err: String(e), signer: SIGNER, sel: SEL };
        }
        var mtg = readMtgsig(req);
        return mtg ? { mtgsig: mtg } : { err: 'mtgsig not set after sign', signer: SIGNER, sel: SEL };
    }
};

send({ tag: 'ready', signer: findSigner() });
