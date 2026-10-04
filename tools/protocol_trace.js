'use strict';
// Optional observer for the proven build. Load after protocol_probe.js.
// Refuse unknown builds; never apply these offsets just because versions match.
(function () {
    const expectedUUID = '3fb544966dc03ccca41b9055fc509adf';
    const module = Process.enumerateModules()[0], base = module.base;
    let hooks = [], events = [], activeThreads = new Map();
    const rva = p => p.sub(base).toString();
    const emit = e => { if (events.length < 200) events.push(e); };
    function state() {
        const provider = base.add(0x4f0ba58).readPointer();
        const pic = base.add(0x5015558).readPointer(), xbt = base.add(0x5015550).readPointer();
        return {provider_parameter: provider.isNull() ? null : provider.add(0x58).readS32(),
            status_bits: base.add(0x5015564).readU32(), session_value: base.add(0x5015570).readU32(),
            resource_status: base.add(0x4e81fc0).readU32(),
            resource_tags: {pic: pic.isNull() ? null : pic.add(0xec).readU32(),
                            xbt: xbt.isNull() ? null : xbt.add(0xc).readU32()}};
    }
    function attach(offset, callbacks) { hooks.push(Interceptor.attach(base.add(offset), callbacks)); }
    rpc.exports.startTrace = function () {
        if (hooks.length) throw Error('Trace is already active');
        if (metadata().macho_uuid !== expectedUUID) throw Error('Unverified native build; relocate field writers first');
        // Recognizable getter and literal instructions must still match in memory.
        for (const [offset, expected] of [[0x30c768,'ldr w0, [x0, #0x58]'],[0x2f857c,'fmov d0, #2.00000000'],[0x2f7ae4,'mov w8, #3'],
            [0x314d3c,'ldr w0, [x0, #0xec]'],[0x3935bc,'ldr w0, [x0, #0xc]']]) {
            if (Instruction.parse(base.add(offset)).toString() !== expected) throw Error('Native code mismatch');
        }
        events = []; activeThreads = new Map();
        attach(0x30f340, {
            onEnter(args) {
                this.selected = args[2].toInt32() === 8;
                if (this.selected) {
                    activeThreads.set(this.threadId,(activeThreads.get(this.threadId)||0)+1);
                    emit({kind:'bridge', command:8, caller:rva(this.returnAddress)});
                }
            },
            onLeave() {
                if (this.selected) activeThreads.set(this.threadId,activeThreads.get(this.threadId)-1);
            }
        });
        attach(0x2de65c, {onEnter(args) {
            if (!activeThreads.get(this.threadId)) return;
            try {
                const key = args[1].readUtf8String();
                if (!['a0','a3','a6','a10','x0'].includes(key)) return;
                const node=args[2], type=node.add(24).readU32();
                const value = type===8 ? node.add(48).readDouble() : type===16 ? node.add(32).readPointer().readUtf8String() : null;
                emit({kind:'field',key,value,caller:rva(this.returnAddress)});
            } catch(e) { emit({kind:'observer_error',stage:'field'}); }
        }});
        for (const [name,offset] of [['provider_constructor',0x30c408],['provider_config',0x30c490]]) {
            attach(offset, {
                onEnter(args) {this.obj=args[0];this.before=name==='provider_config'?this.obj.add(0x58).readS32():null;},
                onLeave(ret) {
                    const p=name==='provider_constructor'?base.add(0x4f0ba58).readPointer():this.obj;
                    emit({kind:name,before:this.before,after:p.add(0x58).readS32(),accepted:name==='provider_config'?ret.toInt32():null});
                }
            });
        }
        return {format:'keeta-native-fields-v1',macho_uuid:expectedUUID,state:state()};
    };
    rpc.exports.traceSnapshot = function () {
        return {format:'keeta-native-fields-v1',macho_uuid:expectedUUID,state:state(),events:events.slice()};
    };
    rpc.exports.stopTrace = function () {
        for (const h of hooks) h.detach();
        hooks=[]; activeThreads.clear();
        return true;
    };
})();
