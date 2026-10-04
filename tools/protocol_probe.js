'use strict';
// Read metadata and sign locally. This agent never sends an HTTP request.
// No addresses from historical binaries and no SDK return-value replacements.
function imageMetadata() {
    // Safe before application startup: no Foundation/ObjC initialization.
    const mod = Process.enumerateModules()[0];
    let p = mod.base.add(32), uuid = null, encryption = null;
    for (let i = 0; i < mod.base.add(16).readU32(); i++) {
        const command = p.readU32(), size = p.add(4).readU32();
        if (size < 8 || size > 1048576) throw Error('Invalid Mach-O command');
        if (command === 0x1b) uuid = Array.from(new Uint8Array(p.add(8).readByteArray(16)))
            .map(x => x.toString(16).padStart(2, '0')).join('');
        if (command === 0x2c) encryption = {offset:p.add(8).readU32(),size:p.add(12).readU32(),cryptid:p.add(16).readU32()};
        p = p.add(size);
    }
    return {macho_uuid: uuid, image_encryption: encryption, module: mod.name};
}
function metadata() {
    const C = ObjC.classes, bundle = C.NSBundle.mainBundle(), info = bundle.infoDictionary();
    const value = key => { const v = info.objectForKey_(key); return v ? v.toString() : null; };
    const classes = {};
    for (const name of ['SAKRequestSignatureProcessor', 'SAKGuardCommon', 'NativeBridge']) {
        if (C[name]) classes[name] = C[name].$ownMethods;
    }
    return {bundle_id: value('CFBundleIdentifier'), app_version: value('CFBundleShortVersionString'),
        build: value('CFBundleVersion'), ...imageMetadata(),
        system_version: C.UIDevice.currentDevice().systemVersion().toString(),
        frida_version: Frida.version, arch: Process.arch, pid: Process.id, classes};
}
rpc.exports = {
    metadata,
    configuration() {
        const key = 'sakguard_dynamic_enc_salt_config_key', C = ObjC.classes;
        if (!C.SAKGuardDCDeviceInfo || !C.SAKGuardDCDeviceInfo['+ sharedManager'])
            return {key, available:false};
        const manager = C.SAKGuardDCDeviceInfo.sharedManager();
        if (!manager.respondsToSelector_(ObjC.selector('storage'))) return {key, available:false};
        const storage = manager.storage();
        if (!storage || !storage.respondsToSelector_(ObjC.selector('stringForKey:userDefaultsSuiteName:')))
            return {key, available:false};
        const v = storage.stringForKey_userDefaultsSuiteName_(key, ptr(0));
        return {key, available:true, storage_class:storage.$className, value:v ? v.toString() : null};
    },
    sign(method, url, body) {
        const C = ObjC.classes;
        if (!C.SAKRequestSignatureProcessor || !C.SAKRequestSignatureProcessor['+ signaturedWithMutableURLRequest:'])
            throw Error('Known signing selector unavailable; inspect metadata before updating');
        const req = C.NSMutableURLRequest.requestWithURL_(C.NSURL.URLWithString_(url));
        req.setHTTPMethod_(method);
        if (body) req.setHTTPBody_(C.NSString.stringWithString_(body).dataUsingEncoding_(4));
        C.SAKRequestSignatureProcessor.signaturedWithMutableURLRequest_(req);
        const mt = req.valueForHTTPHeaderField_('mtgsig');
        if (!mt) throw Error('Native signer did not set mtgsig');
        return {method, url, body, headers: {mtgsig: mt.toString()}, source: 'native_sign_only'};
    }
};
