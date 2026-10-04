'use strict';
// Load after protocol_probe.js. Observes callbacks and provider loads without
// replacing results or writing configuration. Refresh is a separate opt-in RPC.
(function () {
    const expectedUUID = '3fb544966dc03ccca41b9055fc509adf';
    const base = Process.enumerateModules()[0].base;
    const key = 'sakguard_dynamic_enc_salt_config_key';
    const types = ['SAKGuard_Dynamic_Risk', 'SAKGuard_Dynamic_Risk_Test'];
    const sha256 = new NativeFunction(Module.getExportByName(null, 'CC_SHA256'),
        'pointer', ['pointer', 'uint', 'pointer']);
    let hooks = [], events = [], dropped = 0, started = false, sequence = 0;
    const rva = value => value.sub(base).toString();
    function digest(pointer, length) {
        if (length < 0 || length > 65536) throw Error('Invalid observed length');
        const output = Memory.alloc(32);
        sha256(pointer, length, output);
        return Array.from(new Uint8Array(output.readByteArray(32)))
            .map(x => x.toString(16).padStart(2, '0')).join('');
    }
    function stringSummary(value) {
        if (value === null) return {present: false};
        // Frida bridges char* returns to JavaScript strings. Pass an explicitly
        // allocated buffer to CC_SHA256, and do not initialize Foundation here.
        let length = 0;
        for (const character of value) {
            const code = character.codePointAt(0);
            length += code <= 0x7f ? 1 : code <= 0x7ff ? 2 : code <= 0xffff ? 3 : 4;
            if (length > 65536) throw Error('Observed configuration too long');
        }
        return {present: true, length, sha256: digest(Memory.allocUtf8String(value), length)};
    }
    function nsString(pointer) { return pointer.isNull() ? null : new ObjC.Object(pointer).toString(); }
    function state() {
        const provider = base.add(0x4f0ba58).readPointer();
        return {provider_present: !provider.isNull(),
            parameter: provider.isNull() ? null : provider.add(88).readS32(),
            salt_sha256: provider.isNull() ? null : digest(provider.add(72), 16),
            a6: base.add(0x5015564).readU32()};
    }
    function emit(value) {
        if (events.length >= 1000) { dropped++; return; }
        const event = Object.assign({sequence: ++sequence, time_ms: Date.now()}, value);
        events.push(event);
        send({kind: 'config_lifecycle_event', event});
    }
    function observe(kind, action) {
        try { return action(); }
        catch (error) { emit({kind: 'observer_error', stage: kind}); return null; }
    }
    function attach(offset, callbacks) { hooks.push(Interceptor.attach(base.add(offset), callbacks)); }
    function validate() {
        if (imageMetadata().macho_uuid !== expectedUUID) throw Error('Unverified build; relocate lifecycle observers');
        for (const [offset, instruction] of [
            [0x30c768, 'ldr w0, [x0, #0x58]'],
            [0x3679b8, 'stp x24, x23, [sp, #-0x40]!'],
            [0x364e98, 'stp x24, x23, [sp, #-0x40]!'],
            [0x364f90, 'stp x24, x23, [sp, #-0x40]!'],
            [0x30c454, 'sub sp, sp, #0x30'],
            [0x30c490, 'sub sp, sp, #0x20']]) {
            if (Instruction.parse(base.add(offset)).toString() !== instruction)
                throw Error('Lifecycle code mismatch at ' + offset.toString(16));
        }
    }
    function stop() {
        for (const hook of hooks) hook.detach();
        hooks = []; started = false;
        return true;
    }
    rpc.exports.startLifecycle = function () {
        if (started) throw Error('Lifecycle observation already active');
        validate(); events = []; dropped = 0; sequence = 0;
        try {
            attach(0x3679b8, {
                onEnter(args) { observe('callback_enter', () => {
                    this.kind = nsString(args[0].add(32).readPointer());
                    if (!types.includes(this.kind)) { this.kind = null; return; }
                    emit({kind: 'callback_enter', type: this.kind, success: !!args[1].toInt32(),
                        thread: this.threadId, state: state()});
                }); },
                onLeave() { if (this.kind) observe('callback_leave', () => emit({kind: 'callback_leave',
                    type: this.kind, thread: this.threadId, state: state()})); }
            });
            attach(0x364e98, {
                onEnter(args) { observe('storage_write', () => {
                    this.selected = nsString(args[0]) === key;
                    if (this.selected) emit({kind: 'storage_write_enter', thread: this.threadId,
                        configuration: stringSummary(nsString(args[1])), state: state(), caller: rva(this.returnAddress)});
                }); },
                onLeave() { if (this.selected) observe('storage_write', () => emit({kind: 'storage_write_leave',
                    thread: this.threadId, state: state()})); }
            });
            attach(0x364f90, {
                onEnter(args) { observe('storage_read', () => { this.selected = nsString(args[0]) === key; }); },
                onLeave(result) { if (this.selected) observe('storage_read', () => emit({kind: 'storage_read',
                    thread: this.threadId, configuration: stringSummary(nsString(result)), caller: rva(this.returnAddress)})); }
            });
            const fetcherClass = ObjC.classes.SAKHornFetcher;
            for (const name of ['- applyResultWithInfo:error:', '- checkApplyResultWithInfo:error:', '- applyConfigWithInfo:error:']) {
                if (!fetcherClass || !fetcherClass[name]) continue;
                hooks.push(Interceptor.attach(fetcherClass[name].implementation, {
                    onEnter(args) { observe('horn_result', () => {
                        const fetcher = new ObjC.Object(args[0]), type = fetcher.type().toString();
                        if (!types.includes(type)) return;
                        const info = args[2].isNull() ? null : new ObjC.Object(args[2]);
                        const error = args[3].isNull() ? null : new ObjC.Object(args[3]);
                        emit({kind: 'horn_result', stage: name, type, thread: this.threadId,
                            info_class: info ? info.$className : null,
                            http_status: info && info.respondsToSelector_(ObjC.selector('statusCode')) ? Number(info.statusCode()) : null,
                            load_source: info && info.respondsToSelector_(ObjC.selector('loadSource')) ? Number(info.loadSource()) : null,
                            error_code: error && error.respondsToSelector_(ObjC.selector('code')) ? Number(error.code()) : null});
                    }); }
                }));
            }
            for (const [kind, offset, argument] of [['provider_initialize', 0x30c454, 2], ['provider_configure', 0x30c490, 1]]) {
                attach(offset, {
                    onEnter(args) { observe(kind, () => {
                        this.provider = args[0];
                        const configuration = args[argument].isNull() ? null : args[argument].readUtf8String();
                        emit({kind: kind + '_enter', thread: this.threadId,
                            configuration: stringSummary(configuration), before: this.provider.add(88).readS32(),
                            active_provider: this.provider.equals(base.add(0x4f0ba58).readPointer()), caller: rva(this.returnAddress)});
                    }); },
                    onLeave(result) { if (this.provider) observe(kind, () => emit({kind: kind + '_leave',
                        thread: this.threadId, result: result.toInt32(), after: this.provider.add(88).readS32(),
                        active_provider: this.provider.equals(base.add(0x4f0ba58).readPointer()), state: state()})); }
                });
            }
            started = true;
            return {format: 'keeta-config-lifecycle-v1', macho_uuid: expectedUUID, state: state()};
        } catch (error) { stop(); throw error; }
    };
    rpc.exports.refreshConfiguration = function () {
        if (!started) throw Error('Start observation before requesting refresh');
        const H = ObjC.classes.SAKHorn;
        if (!H || !H['+ forceRefreshTypeArray:completion:']) throw Error('Known Horn refresh selector unavailable');
        // One existing production config type only. No mock callback or cache removal.
        const type = 'SAKGuard_Dynamic_Risk';
        if (!H.isTypeRegistered_(type)) throw Error('Production configuration type is not registered');
        return new Promise((resolve, reject) => ObjC.schedule(ObjC.mainQueue, () => {
            try {
                emit({kind: 'sdk_refresh_requested', type});
                H.forceRefreshTypeArray_completion_(ObjC.classes.NSArray.arrayWithObject_(type), ptr(0));
                resolve({type, requested: true});
            } catch (error) { reject(Error('SDK refresh invocation failed')); }
        }));
    };
    rpc.exports.lifecycleSnapshot = function () {
        if (!started) throw Error('Lifecycle observation not active');
        return {format: 'keeta-config-lifecycle-v1', macho_uuid: expectedUUID,
            state: state(), events: events.slice(), dropped};
    };
    rpc.exports.stopLifecycle = stop;
})();
