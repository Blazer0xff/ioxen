import { test } from 'node:test';
import assert from 'node:assert/strict';

import * as fmt from '../../agent/ios/format.js';

test('fnmatch mirrors Python fnmatch semantics', () => {
  assert.equal(fmt.fnmatch('com.apple.securityd', 'com.apple.*'), true);
  assert.equal(fmt.fnmatch('com.apple.securityd', 'com.apple.?ecurityd'), true);
  assert.equal(fmt.fnmatch('com.apple.securityd', 'com.example.*'), false);
  assert.equal(fmt.fnmatch('a.b', 'a?b'), true);
  assert.equal(fmt.fnmatch('xpc', '[wx]pc'), true);
  assert.equal(fmt.fnmatch('xpc', '[!x]pc'), false);
  assert.equal(fmt.fnmatch('[x', '[x'), true);
  assert.equal(fmt.fnmatch('a/b(c)+', 'a/b(c)+'), true);
  assert.equal(fmt.fnmatch('multi\nline', 'multi*'), true);
});

test('checkMatch supports presence checks and list values', () => {
  const ctx = {
    class: 'MyApp', method: 'xpc_connection_send_message', action: '', component: 'com.apple.foo',
    data: '', direction: 'outgoing', peer: '/usr/libexec/foo',
  };
  assert.equal(fmt.checkMatch(ctx, [{ component: 'com.apple.*', direction: 'outgoing' }]), true);
  assert.equal(fmt.checkMatch(ctx, [{ action: 'set' }]), false);
  assert.equal(fmt.checkMatch(ctx, [{ action: 'unset' }]), true);
  assert.equal(fmt.checkMatch(ctx, [{ peer: 'set' }]), true);
  assert.equal(fmt.checkMatch(ctx, [{ data: 'set' }]), false);
  assert.equal(fmt.checkMatch(ctx, [{ unknown: '*' }]), false);
  assert.equal(fmt.checkMatch({ tags: ['a', 'b'] }, [{ tags: 'b' }]), true);
  assert.equal(fmt.checkMatch({ tags: [] }, [{ tags: 'set' }]), false);
});

test('isVisible: focus wins over ignore', () => {
  const ctx = { component: 'com.apple.cfprefsd.daemon', direction: 'outgoing' };
  assert.equal(fmt.isVisible(ctx, [{ component: 'com.apple.cfprefsd*' }], []), false);
  assert.equal(fmt.isVisible(ctx, [], [{ direction: 'incoming' }]), false);
  assert.equal(fmt.isVisible(ctx, [{ component: '*' }], [{ direction: 'outgoing' }]), true);
  assert.equal(fmt.isVisible(ctx, [], []), true);
});

test('buildFilterContext mirrors the Python filter context', () => {
  const ctx = fmt.buildFilterContext({
    className: 'MyApp',
    methodName: 'xpc_event_handler',
    infoIntent: { component: 'com.example.svc', action: 'doThing:', extras: {} },
    ipc: { direction: 'incoming', peer: { pid: 42, path: null } },
  });
  assert.deepEqual(ctx, {
    class: 'MyApp', method: 'xpc_event_handler', action: 'doThing:', component: 'com.example.svc',
    data: '', direction: 'incoming', peer: '42',
  });
});

test('hex and base64 helpers', () => {
  const bytes = new Uint8Array([0, 1, 0xab, 0xff]);
  assert.equal(fmt.toHex(bytes), '0001abff');
  assert.equal(fmt.toHex(bytes, 2), '0001');
  assert.deepEqual(Array.from(fmt.parseHex('0x00 01:ab ff')), [0, 1, 0xab, 0xff]);
  assert.equal(fmt.parseHex('abc'), null);
  assert.equal(fmt.parseHex('zz'), null);
  for (const text of ['', 'f', 'fo', 'foo', 'foob', 'fooba', 'foobar']) {
    const input = new TextEncoder().encode(text);
    assert.equal(fmt.toBase64(input), Buffer.from(text).toString('base64'));
  }
});

test('bplist detection, string extraction and selector guess', () => {
  const blob = new TextEncoder().encode('bplist16\x00\x01doThing:withReply:\x00\x02NSString\x00hi\x00');
  assert.equal(fmt.detectBplist(blob), 'bplist16');
  assert.equal(fmt.detectBplist(new TextEncoder().encode('notplist')), null);
  const strings = fmt.extractStrings(blob, 4, 10);
  assert.deepEqual(strings, ['doThing:withReply:', 'NSString']);
  assert.equal(fmt.guessSelector(strings), 'doThing:withReply:');
  assert.equal(fmt.guessSelector(['NSString', 'not a selector:']), null);
});

const sampleTree = {
  t: 'dictionary',
  v: [
    ['op', { t: 'string', v: 'fetch' }],
    ['count', { t: 'int64', v: '3' }],
    ['opts', { t: 'dictionary', v: [['com.apple.flag', { t: 'bool', v: 'true' }]] }],
    ['items', { t: 'array', v: [{ t: 'uint64', v: '1' }, { t: 'string', v: 'x' }] }],
    ['empty', { t: 'dictionary', v: [] }],
    ['root', { t: 'data', len: 40, hex: '62706c6973743136', bplist: 'bplist16', strings: ['ping:'] }],
  ],
};

test('flattenTree produces slash-separated extras', () => {
  assert.deepEqual(fmt.flattenTree(sampleTree), {
    op: { type: 'string', value: 'fetch' },
    count: { type: 'int64', value: '3' },
    'opts/com.apple.flag': { type: 'bool', value: 'true' },
    'items[0]': { type: 'uint64', value: '1' },
    'items[1]': { type: 'string', value: 'x' },
    empty: { type: 'dictionary', value: '{0 keys}' },
    root: { type: 'data', value: '40 bytes bplist16 62706c6973743136…' },
  });
});

test('flattenTree caps entries', () => {
  const big = { t: 'dictionary', v: Array.from({ length: 10 }, (_, i) => ['k' + i, { t: 'int64', v: String(i) }]) };
  const flat = fmt.flattenTree(big, 3);
  assert.equal(Object.keys(flat).length, 4);
  assert.equal(flat['…'].type, 'truncated');
});

test('collectBlobs and nsxpcInfo', () => {
  assert.deepEqual(fmt.collectBlobs(sampleTree), [
    { path: 'root', length: 40, format: 'bplist16', strings: ['ping:'] },
  ]);
  assert.deepEqual(fmt.nsxpcInfo(sampleTree), { encoding: 'bplist16', selector: 'ping:', strings: ['ping:'] });
  assert.equal(fmt.nsxpcInfo({ t: 'dictionary', v: [] }), null);
  assert.deepEqual(fmt.splitPath('a/b//c'), ['a', 'b', 'c']);
});

test('normalizeValueType maps ioxen value types to XPC types', () => {
  assert.equal(fmt.normalizeValueType('int'), 'int64');
  assert.equal(fmt.normalizeValueType('LONG'), 'int64');
  assert.equal(fmt.normalizeValueType('float'), 'double');
  assert.equal(fmt.normalizeValueType('boolean'), 'bool');
  assert.equal(fmt.normalizeValueType('data'), 'data');
  assert.equal(fmt.normalizeValueType(undefined), 'string');
  assert.equal(fmt.normalizeValueType('struct'), null);
});

test('parseObjCTypes handles offsets, blocks, structs and qualifiers', () => {
  assert.deepEqual(fmt.parseObjCTypes('v40@0:8@16@?24q32'), ['v', '@', ':', '@', '@?', 'q']);
  assert.deepEqual(fmt.parseObjCTypes('B32@0:8@"NSXPCListener"16@"NSXPCConnection"24'),
    ['B', '@', ':', '@"NSXPCListener"', '@"NSXPCConnection"']);
  assert.deepEqual(fmt.parseObjCTypes('v@:{CGRect={CGPoint=dd}{CGSize=dd}}r*^v@?<v@?@"NSError">'),
    ['v', '@', ':', '{CGRect={CGPoint=dd}{CGSize=dd}}', '*', '^v', '@?']);
  assert.equal(fmt.objcTypeKind('@"NSString"'), 'object');
  assert.equal(fmt.objcTypeKind('@?'), 'block');
  assert.equal(fmt.objcTypeKind('Q'), 'integer');
  assert.equal(fmt.objcTypeKind('{CGRect=dd}'), 'struct');
  assert.equal(fmt.objcClassHint('@"NSXPCConnection"'), 'NSXPCConnection');
  assert.equal(fmt.objcClassHint('@'), null);
});

function be32(n) {
  return [(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff];
}

test('entitlementsFromSuperBlob extracts the XML entitlements slot', () => {
  const xml = '<?xml version="1.0"?><plist><dict><key>application-identifier</key><string>T.app</string></dict></plist>';
  const xmlBytes = Array.from(new TextEncoder().encode(xml));
  const codeDirectory = [...be32(0xfade0c02), ...be32(12), 0, 0, 0, 0];
  const header = 12 + 2 * 8;
  const entOffset = header + codeDirectory.length;
  const ent = [...be32(0xfade7171), ...be32(8 + xmlBytes.length), ...xmlBytes];
  const total = entOffset + ent.length;
  const bytes = new Uint8Array([
    ...be32(0xfade0cc0), ...be32(total), ...be32(2),
    ...be32(0), ...be32(header),
    ...be32(5), ...be32(entOffset),
    ...codeDirectory, ...ent,
  ]);
  assert.equal(fmt.entitlementsFromSuperBlob(bytes), xml);
  assert.equal(fmt.entitlementsFromSuperBlob(new Uint8Array([1, 2, 3])), null);
  assert.equal(fmt.entitlementsFromSuperBlob(bytes.subarray(0, 28)), null);
});

test('nsxpcSendLayout maps private NSXPC send selectors', () => {
  assert.deepEqual(fmt.nsxpcSendLayout('_sendInvocation:withProxy:'), {
    kind: 'invocation', invocation: 2, arguments: -1, count: -1, signature: -1, selector: -1, proxy: 3, values: [],
  });
  assert.deepEqual(fmt.nsxpcSendLayout('_sendInvocation:orArguments:count:methodSignature:selector:withProxy:'), {
    kind: 'invocation', invocation: 2, arguments: 3, count: 4, signature: 5, selector: 6, proxy: 7, values: [],
  });
  assert.deepEqual(fmt.nsxpcSendLayout('_sendSelector:withProxy:arg1:arg2:'), {
    kind: 'selector', invocation: -1, arguments: -1, count: -1, signature: -1, selector: 2, proxy: 3, values: [4, 5],
  });
  assert.deepEqual(fmt.nsxpcSendLayout('_sendSelector:withProxy:').values, []);
  assert.equal(fmt.nsxpcSendLayout('_sendDesistForProxy:'), null);
  assert.equal(fmt.nsxpcSendLayout(''), null);
});

test('scalarLayout sizes ObjC scalar encodings', () => {
  assert.deepEqual(fmt.scalarLayout('q'), [8, 'S64']);
  assert.deepEqual(fmt.scalarLayout('rI'), [4, 'U32']);
  assert.deepEqual(fmt.scalarLayout('B'), [1, 'U8']);
  assert.equal(fmt.scalarLayout('@'), null);
});

test('validateSendLayout rejects shapes that do not match the runtime encoding', () => {
  const inv = fmt.nsxpcSendLayout('_sendInvocation:withProxy:');
  assert.equal(fmt.validateSendLayout(inv, fmt.parseObjCTypes('v32@0:8@16@24')), true);
  assert.equal(fmt.validateSendLayout(inv, fmt.parseObjCTypes('v32@0:8^v16@24')), false);
  const full = fmt.nsxpcSendLayout('_sendInvocation:orArguments:count:methodSignature:selector:withProxy:');
  assert.equal(fmt.validateSendLayout(full, fmt.parseObjCTypes('v64@0:8@16^@24Q32@40:48@56')), true);
  assert.equal(fmt.validateSendLayout(full, fmt.parseObjCTypes('v64@0:8@16^@24Q32@40Q48@56')), false);
  const sel = fmt.nsxpcSendLayout('_sendSelector:withProxy:arg1:arg2:');
  assert.equal(fmt.validateSendLayout(sel, fmt.parseObjCTypes('v48@0:8:16@24@32@40')), true);
  assert.equal(fmt.validateSendLayout(sel, fmt.parseObjCTypes('v48@0:8:16@24@32q40')), false);
  assert.equal(fmt.validateSendLayout(sel, []), false);
  assert.equal(fmt.validateSendLayout(null, ['v', '@', ':']), false);
});

test('mergeHookEntries lets later entries override or disable defaults', () => {
  const merged = fmt.mergeHookEntries([
    { kind: 'xpc', function: 'xpc_connection_send_message' },
    { kind: 'nsxpc', feature: 'connections' },
    { kind: 'nsxpc', feature: 'replies', enabled: false },
    { clazz: 'android.app.Activity', method: 'getIntent' },
    { kind: 'nsxpc', feature: 'connections', enabled: false },
    { kind: 'nsxpc', feature: 'replies', enabled: true },
    { kind: 'xpc', function: 'xpc_connection_send_message', intercept: false },
    null,
  ]);
  assert.deepEqual(merged, [
    { kind: 'nsxpc', feature: 'replies', enabled: true },
    { kind: 'xpc', function: 'xpc_connection_send_message', intercept: false },
  ]);
});

test('example bisect configs disable the intended default hooks', async () => {
  const { readFileSync } = await import('node:fs');
  const load = name => JSON.parse(readFileSync(new URL('../../' + name, import.meta.url)));
  const defaults = load('config/ios_hooks.json');
  const merged = name => fmt.mergeHookEntries(defaults.concat(load('examples/ios/' + name)));
  assert.deepEqual(merged('no-hooks.json'), []);
  assert.ok(merged('xpc-only.json').every(e => e.kind === 'xpc'));
  assert.ok(merged('xpc-only.json').length > 0);
  assert.ok(!merged('no-nsxpc.json').some(e => e.kind === 'nsxpc'));
  assert.ok(!merged('no-url.json').some(e => e.kind === 'url'));
  assert.ok(merged('observe-only.json').every(e => e.intercept === false));
  assert.ok(!merged('observe-only.json').some(e => e.feature === 'replies'));
  // xpc-full.json may be customised (e.g. URL hooks re-enabled); it must keep
  // every XPC layer plus decoded NSXPC replies.
  const full = merged('xpc-full.json');
  assert.ok(full.some(e => e.feature === 'replies'));
  for (const fn of ['xpc_connection_send_message', 'xpc_connection_send_message_with_reply',
    'xpc_connection_send_message_with_reply_sync', 'xpc_connection_set_event_handler']) {
    assert.ok(full.some(e => e.function === fn), fn);
  }
  assert.ok(full.some(e => e.function === 'xpc_connection_set_event_handler'));
  assert.ok(full.some(e => e.feature === 'connections') && full.some(e => e.feature === 'listeners'));
});

test('web view and network helpers', () => {
  assert.equal(fmt.navigationTypeName(0), 'link');
  assert.equal(fmt.navigationTypeName(-1), 'other');
  assert.equal(fmt.navigationTypeName('1'), 'form submit');
  assert.equal(fmt.navigationTypeName(9), '9');
  assert.equal(fmt.bodyPreview(new TextEncoder().encode('{"user":"a"}')), '{"user":"a"}');
  assert.equal(fmt.bodyPreview(new Uint8Array([0, 1, 2, 255])), 'hex:000102ff');
  assert.equal(fmt.bodyPreview(new TextEncoder().encode('abcdef'), 3), 'abc…');
  assert.equal(fmt.bodyPreview(new Uint8Array(0)), '');
  assert.equal(fmt.hostOf('https://User:pw@API.Example.com:8443/v1?q=1'), 'api.example.com');
  assert.equal(fmt.hostOf('myapp://callback'), 'callback');
  assert.equal(fmt.hostOf('not a url'), null);
});

test('example configs are valid hook definitions', async () => {
  // The example files are meant to be edited, so only their validity is checked.
  const { readFileSync, readdirSync } = await import('node:fs');
  const load = name => JSON.parse(readFileSync(new URL('../../' + name, import.meta.url)));
  const known = new Set(['xpc', 'nsxpc', 'url', 'notify', 'webview', 'network', 'objc']);
  const defaults = load('config/ios_hooks.json');
  for (const name of readdirSync(new URL('../../examples/ios/', import.meta.url))) {
    if (!name.endsWith('.json')) continue;
    const entries = load('examples/ios/' + name);
    assert.ok(Array.isArray(entries), name);
    for (const entry of entries) {
      assert.ok(known.has(entry.kind), name + ': unknown kind ' + entry.kind);
      assert.ok(entry.function || entry.feature || entry.method, name + ': entry without target');
    }
    fmt.mergeHookEntries(defaults.concat(entries));
  }
  // the defaults keep the opt-in layers off
  const merged = fmt.mergeHookEntries(defaults);
  assert.ok(!merged.some(e => e.kind === 'webview' || e.kind === 'network'));
});
