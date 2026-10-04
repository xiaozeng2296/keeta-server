'use strict';
// Ensure pre-startup lifecycle guards never invoke Foundation metadata.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '..');
const probe = fs.readFileSync(path.join(root, 'tools/protocol_probe.js'), 'utf8');
const lifecycle = fs.readFileSync(path.join(root, 'tools/protocol_lifecycle.js'), 'utf8');

function environment(options = {}) {
    const binary = Buffer.alloc(128), base = 0x100000000;
    binary.writeUInt32LE(2, 16);
    binary.writeUInt32LE(0x1b, 32); binary.writeUInt32LE(24, 36);
    Buffer.from(options.uuid || '3fb544966dc03ccca41b9055fc509adf', 'hex').copy(binary, 40);
    binary.writeUInt32LE(0x2c, 56); binary.writeUInt32LE(24, 60);
    binary.writeUInt32LE(0x221d000, 64); binary.writeUInt32LE(4096, 68); binary.writeUInt32LE(1, 72);
    class Pointer {
        constructor(value, memory = null) { this.value = value; this.memory = memory; }
        add(n) { return new Pointer(this.value + n); }
        sub(p) { return new Pointer(this.value - p.value); }
        isNull() { return this.value === 0; }
        toString() { return '0x' + this.value.toString(16); }
        readU32() {
            if (this.value === base + 0x5015564) return 0;
            return binary.readUInt32LE(this.value - base);
        }
        readPointer() {
            assert.equal(this.value, base + 0x4f0ba58);
            return new Pointer(0);
        }
        readByteArray(n) {
            if (this.memory) return Uint8Array.from(this.memory.subarray(0, n)).buffer;
            return Uint8Array.from(binary.subarray(this.value - base, this.value - base + n)).buffer;
        }
    }
    const instructions = new Map([
        [0x30c768, 'ldr w0, [x0, #0x58]'],
        [0x3679b8, 'stp x24, x23, [sp, #-0x40]!'],
        [0x364e98, 'stp x24, x23, [sp, #-0x40]!'],
        [0x364f90, 'stp x24, x23, [sp, #-0x40]!'],
        [0x30c454, 'sub sp, sp, #0x30'], [0x30c490, 'sub sp, sp, #0x20']
    ]);
    const hooks = [], detached = [], messages = [];
    const context = vm.createContext({
        Process: {enumerateModules: () => [{base: new Pointer(base), name: 'Keeta'}]},
        Module: {getExportByName: () => new Pointer(1)},
        NativeFunction: function () { return (input, length, output) => {
            assert.ok(input instanceof Pointer, 'Native hashing requires an allocated pointer');
            crypto.createHash('sha256').update(Buffer.from(input.readByteArray(length))).digest().copy(output.memory);
        }; },
        Memory: {
            alloc: length => new Pointer(1, Buffer.alloc(length)),
            allocUtf8String: value => new Pointer(1, Buffer.from(value + '\0', 'utf8'))
        },
        send: value => messages.push(value),
        Interceptor: {attach: (address, callbacks) => {
            hooks.push({address: address.value, callbacks});
            return {detach: () => detached.push(address.value)};
        }},
        Instruction: {parse: address => ({toString: () => options.badInstruction ? 'wrong' : instructions.get(address.value - base)})},
        rpc: {exports: {}},
        ObjC: {Object: function (pointer) { return {toString: () => pointer.text}; },
            classes: new Proxy({}, {get: (object, key) => {
            // Looking up an optional runtime class must not call into Foundation.
            assert.equal(key, 'SAKHornFetcher'); return undefined;
        }})}
    });
    vm.runInContext(probe, context);
    context.metadata = () => { throw Error('Foundation metadata invoked before startup'); };
    vm.runInContext(lifecycle, context);
    return {context, hooks, detached, messages, Pointer, base};
}

{
    const {context, hooks, detached} = environment();
    const identity = context.imageMetadata();
    assert.equal(identity.macho_uuid, '3fb544966dc03ccca41b9055fc509adf');
    assert.equal(identity.image_encryption.cryptid, 1);
    assert.equal(identity.image_encryption.offset, 0x221d000);
    const initial = context.rpc.exports.startLifecycle();
    assert.equal(initial.state.provider_present, false);
    assert.equal(hooks.length, 5);
    context.rpc.exports.stopLifecycle();
    assert.equal(detached.length, hooks.length);
}
{
    const {context, hooks} = environment({uuid: '00112233445566778899aabbccddeeff'});
    assert.throws(() => context.rpc.exports.startLifecycle(), /Unverified build/);
    assert.equal(hooks.length, 0);
}
{
    const {context, hooks} = environment({badInstruction: true});
    assert.throws(() => context.rpc.exports.startLifecycle(), /Lifecycle code mismatch/);
    assert.equal(hooks.length, 0);
}
{
    const {context, hooks, messages, Pointer, base} = environment();
    context.rpc.exports.startLifecycle();
    const write = hooks.find(hook => hook.address === base + 0x364e98).callbacks;
    const value = 'synthetic-é-😀-\0-end';
    const invocation = {threadId: 1, returnAddress: new Pointer(base + 0x368180)};
    const ns = text => ({text, isNull: () => false});
    write.onEnter.call(invocation, [ns('sakguard_dynamic_enc_salt_config_key'), ns(value)]);
    write.onLeave.call(invocation);
    assert.equal(messages.length, 2);
    const configuration = messages[0].event.configuration;
    assert.equal(messages[0].event.kind, 'storage_write_enter');
    assert.equal(configuration.length, Buffer.byteLength(value));
    assert.equal(configuration.sha256, crypto.createHash('sha256').update(value).digest('hex'));
    assert.equal(messages[1].event.kind, 'storage_write_leave');
    assert.ok(!JSON.stringify(messages).includes(value));
    context.rpc.exports.stopLifecycle();
}
console.log('4 protocol probe guard/hash cases passed');
