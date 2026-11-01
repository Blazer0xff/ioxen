import ObjC_bridge from 'frida-objc-bridge';
import * as fmt from './ios/format.js';
import { createDecisionCore } from './ios/decisions.js';

// Frida >= 17 compatibility: the ObjC bridge is no longer injected as a
// global. In Frida < 17 globalThis.ObjC is still set automatically; we reuse
// it to avoid double-loading. Re-export it for scripts appended at runtime.
const ObjC = typeof globalThis.ObjC !== 'undefined' ? globalThis.ObjC : ObjC_bridge;
try { globalThis.ObjC = ObjC; } catch (_) {}

// ioxen iOS agent.
//
// Captures inter-process communication of an iOS process and lets the host
// forward, drop or modify each event:
//
//   * libxpc: outgoing messages, incoming messages (event handlers), replies
//     and new peer connections on listeners.
//   * NSXPC: connection/interface mapping, listener accept decisions and
//     calls into exported objects.
//   * URL schemes / universal links (incoming and outgoing).
//   * Darwin notifications (notify_post / notify_register_*).
//
// Blocking uses recv().wait(): the hooked thread waits for a
// "ioxen-wake:<decisionId>" message that the host posts after the
// forward/drop RPC. recv().wait() releases the JS lock (so RPCs keep working)
// and is woken by Frida when the script unloads, so a held thread is never
// stranded.

const POINTER_SIZE = Process.pointerSize;
const JS_THREAD_ID = Process.getCurrentThreadId();
const MAX_STACK_FRAMES = 24;
const MAX_TREE_NODES = 400;
const MAX_TREE_DEPTH = 8;
const MAX_STRING = 4096;
const DATA_PREVIEW = 64;
const DATA_SCAN = 65536;
const MAX_DESCRIPTION = 8192;

// --- State -----------------------------------------------------------------

let rpcDepth = 0;
const busyThreads = new Set();
const keepAlive = [];
const report = { hooks: 0, failed: 0 };

// --- Generic helpers -------------------------------------------------------

function log(prefix, text) {
  send(prefix + ' ' + text);
}

function findExport(name, moduleName) {
  if (moduleName) {
    try {
      const mod = Process.findModuleByName(moduleName);
      if (mod !== null) {
        const p = mod.findExportByName(name);
        if (p !== null) return p;
      }
    } catch (_) {}
  }
  try {
    if (typeof Module.findGlobalExportByName === 'function') return Module.findGlobalExportByName(name);
  } catch (_) {}
  try {
    if (typeof Module.findExportByName === 'function') return Module.findExportByName(moduleName || null, name);
  } catch (_) {}
  return null;
}

function nativeFn(name, moduleName, ret, args) {
  const p = findExport(name, moduleName);
  return p === null ? null : new NativeFunction(p, ret, args);
}

function readCString(p, limit) {
  if (p === null || p.isNull()) return null;
  try {
    const s = p.readUtf8String();
    return limit && s.length > limit ? s.slice(0, limit) + '…' : s;
  } catch (_) {
    try { return p.readCString(); } catch (_) { return null; }
  }
}

function readBytes(p, length) {
  if (p === null || p.isNull() || length <= 0) return new Uint8Array(0);
  return new Uint8Array(p.readByteArray(length));
}

function toCString(text) {
  const p = Memory.allocUtf8String(String(text));
  keepTemp(p);
  return p;
}

// Temporaries must outlive the original call they are passed to.
let tempRefs = [];
function keepTemp(value) {
  tempRefs.push(value);
  if (tempRefs.length > 256) tempRefs = tempRefs.slice(-128);
}

function shouldPassthrough() {
  const tid = Process.getCurrentThreadId();
  return tid === JS_THREAD_ID || rpcDepth > 0 || busyThreads.has(tid);
}

function withBusyThread(fn) {
  const tid = Process.getCurrentThreadId();
  busyThreads.add(tid);
  try {
    return fn();
  } finally {
    busyThreads.delete(tid);
  }
}

// Module lookups run on every event, often on the target's main thread during
// launch, so they go through a cached ModuleMap instead of enumerating
// modules or symbolicating (DebugSymbol is far too slow for that path).
let moduleMap = null;
let moduleMapRefreshed = 0;

function moduleFor(address) {
  try {
    if (moduleMap === null) moduleMap = new ModuleMap();
    let mod = moduleMap.find(address);
    if (mod === null && Date.now() - moduleMapRefreshed > 1000) {
      moduleMapRefreshed = Date.now();
      moduleMap.update();
      mod = moduleMap.find(address);
    }
    return mod;
  } catch (_) {
    return null;
  }
}

function moduleNameFor(address) {
  const mod = moduleFor(address);
  return mod ? mod.name : null;
}

function frameLabel(address) {
  const mod = moduleFor(address);
  return mod ? mod.name + '!0x' + address.sub(mod.base).toString(16) : address.toString();
}

// Darwin's accurate backtracer walks frame pointers (always present on arm64
// Apple platforms). Elsewhere (the Linux test harness) the libunwind-based
// accurate backtracer can crash inside replacement callbacks, so use fuzzy.
const BACKTRACER = Process.platform === 'darwin' ? Backtracer.ACCURATE : Backtracer.FUZZY;

function captureStack(context) {
  try {
    return Thread.backtrace(context, BACKTRACER)
      .slice(0, MAX_STACK_FRAMES)
      .map(frameLabel);
  } catch (_) {
    return [];
  }
}

// --- libSystem / libxpc bindings --------------------------------------------

const LIBXPC = 'libxpc.dylib';
const X = {};
const XPC_TYPES = new Map();
const XPC_CONST = {};

const XPC_SIGNATURES = {
  xpc_get_type: ['pointer', ['pointer']],
  xpc_copy_description: ['pointer', ['pointer']],
  xpc_retain: ['pointer', ['pointer']],
  xpc_release: ['void', ['pointer']],
  xpc_dictionary_apply: ['bool', ['pointer', 'pointer']],
  xpc_dictionary_get_value: ['pointer', ['pointer', 'pointer']],
  xpc_dictionary_get_string: ['pointer', ['pointer', 'pointer']],
  xpc_dictionary_set_value: ['void', ['pointer', 'pointer', 'pointer']],
  xpc_dictionary_set_string: ['void', ['pointer', 'pointer', 'pointer']],
  xpc_dictionary_set_int64: ['void', ['pointer', 'pointer', 'int64']],
  xpc_dictionary_set_uint64: ['void', ['pointer', 'pointer', 'uint64']],
  xpc_dictionary_set_bool: ['void', ['pointer', 'pointer', 'bool']],
  xpc_dictionary_set_double: ['void', ['pointer', 'pointer', 'double']],
  xpc_dictionary_set_data: ['void', ['pointer', 'pointer', 'pointer', 'size_t']],
  xpc_array_get_count: ['size_t', ['pointer']],
  xpc_array_get_value: ['pointer', ['pointer', 'size_t']],
  xpc_string_get_string_ptr: ['pointer', ['pointer']],
  xpc_int64_get_value: ['int64', ['pointer']],
  xpc_uint64_get_value: ['uint64', ['pointer']],
  xpc_bool_get_value: ['bool', ['pointer']],
  xpc_double_get_value: ['double', ['pointer']],
  xpc_date_get_value: ['int64', ['pointer']],
  xpc_data_get_length: ['size_t', ['pointer']],
  xpc_data_get_bytes_ptr: ['pointer', ['pointer']],
  xpc_uuid_get_bytes: ['pointer', ['pointer']],
  xpc_connection_get_name: ['pointer', ['pointer']],
  xpc_connection_get_pid: ['int', ['pointer']],
  xpc_connection_get_euid: ['uint32', ['pointer']],
  xpc_connection_cancel: ['void', ['pointer']],
};

const XPC_TYPE_SYMBOLS = [
  'dictionary', 'array', 'string', 'int64', 'uint64', 'bool', 'double', 'date', 'data',
  'uuid', 'fd', 'shmem', 'null', 'endpoint', 'connection', 'error', 'activity', 'mach_send',
  'mach_recv', 'pipe', 'serializer', 'session', 'rich_error',
];

const ERROR_SYMBOLS = {
  _xpc_error_connection_interrupted: 'XPC_ERROR_CONNECTION_INTERRUPTED',
  _xpc_error_connection_invalid: 'XPC_ERROR_CONNECTION_INVALID',
  _xpc_error_termination_imminent: 'XPC_ERROR_TERMINATION_IMMINENT',
  _xpc_error_peer_code_signing_requirement: 'XPC_ERROR_PEER_CODE_SIGNING_REQUIREMENT',
};

const LIBC = {};
let xpcReady = false;

function initNative() {
  for (const name of Object.keys(XPC_SIGNATURES)) {
    const [ret, args] = XPC_SIGNATURES[name];
    X[name] = nativeFn(name, LIBXPC, ret, args);
  }
  for (const name of XPC_TYPE_SYMBOLS) {
    const p = findExport('_xpc_type_' + name, LIBXPC);
    if (p !== null) XPC_TYPES.set(p.strip().toString(), name);
  }
  XPC_CONST.boolTrue = findExport('_xpc_bool_true', LIBXPC);
  XPC_CONST.errors = new Map();
  for (const sym of Object.keys(ERROR_SYMBOLS)) {
    const p = findExport(sym, LIBXPC);
    if (p !== null) {
      XPC_CONST.errors.set(p.strip().toString(), ERROR_SYMBOLS[sym]);
      if (sym === '_xpc_error_connection_interrupted') XPC_CONST.interrupted = p;
      if (sym === '_xpc_error_connection_invalid') XPC_CONST.invalid = p;
    }
  }

  LIBC.free = nativeFn('free', 'libsystem_malloc.dylib', 'void', ['pointer']);
  LIBC.proc_pidpath = nativeFn('proc_pidpath', 'libsystem_kernel.dylib', 'int', ['int', 'pointer', 'uint32']);
  LIBC.Block_copy = nativeFn('_Block_copy', 'libsystem_blocks.dylib', 'pointer', ['pointer']);
  LIBC.Block_release = nativeFn('_Block_release', 'libsystem_blocks.dylib', 'void', ['pointer']);
  LIBC.globalBlockClass = findExport('_NSConcreteGlobalBlock', 'libsystem_blocks.dylib');

  xpcReady = X.xpc_get_type !== null && X.xpc_dictionary_apply !== null &&
    LIBC.Block_copy !== null && LIBC.globalBlockClass !== null && POINTER_SIZE === 8;
}

function xpcType(obj) {
  if (obj === null || obj.isNull()) return 'null';
  try {
    return XPC_TYPES.get(X.xpc_get_type(obj).strip().toString()) || 'unknown';
  } catch (_) {
    return 'unknown';
  }
}

function errorName(obj) {
  return XPC_CONST.errors.get(obj.strip().toString()) || null;
}

// --- Blocks ------------------------------------------------------------------
//
// libxpc takes handlers as blocks. Instead of patching the caller's block we
// hand libxpc our own *global* block (Block_copy/Block_release are no-ops on
// global blocks) whose invoke pointer is a shared NativeCallback. Two extra
// words after the standard 32-byte layout carry the copied original block and
// a context id:
//
//   +0  isa  +8 flags  +12 reserved  +16 invoke  +24 descriptor
//   +32 original block (Block_copy'd)  +40 context id
//
// On arm64e the invoke pointer is signed with the IA key and the address of
// the invoke slot, exactly like the ObjC bridge does for ObjC.Block.

const BLOCK_IS_GLOBAL = 1 << 28;
const BLOCK_HAS_SIGNATURE = 1 << 30;
const BLOCK_SIZE = 48;
const descriptorCache = new Map();
const invokeCache = new Map();

function blockDescriptor(signature) {
  let d = descriptorCache.get(signature);
  if (d === undefined) {
    const types = Memory.allocUtf8String(signature);
    d = Memory.alloc(3 * POINTER_SIZE);
    d.writeULong(0);
    d.add(POINTER_SIZE).writeULong(BLOCK_SIZE);
    d.add(2 * POINTER_SIZE).writePointer(types);
    keepAlive.push(types, d);
    descriptorCache.set(signature, d);
  }
  return d;
}

// Block memory is never freed. libxpc (and NSInvocation) can keep a pointer
// to a handler block long after its last invocation and still call
// Block_release/objc_release on it, which reads the block's flags/isa. If
// that memory had been garbage-collected and reused, the app would crash at a
// random later point. Blocks are carved from permanently retained slabs, so
// the cost is 48 bytes per wrapped handler.
const BLOCK_SLAB_COUNT = 256;
const blockSlabs = [];
let blockSlab = null;
let blockSlabUsed = BLOCK_SLAB_COUNT;

function allocBlock() {
  if (blockSlabUsed === BLOCK_SLAB_COUNT) {
    blockSlab = Memory.alloc(BLOCK_SIZE * BLOCK_SLAB_COUNT);
    blockSlabs.push(blockSlab);
    blockSlabUsed = 0;
  }
  const blk = blockSlab.add(BLOCK_SIZE * blockSlabUsed);
  blockSlabUsed += 1;
  return blk;
}

function makeGlobalBlock(invoke, signature, original, contextId) {
  const blk = allocBlock();
  blk.writePointer(LIBC.globalBlockClass);
  blk.add(8).writeU32(BLOCK_IS_GLOBAL | BLOCK_HAS_SIGNATURE);
  blk.add(12).writeU32(0);
  const slot = blk.add(16);
  slot.writePointer(invoke.strip().sign('ia', slot));
  blk.add(24).writePointer(blockDescriptor(signature));
  blk.add(32).writePointer(original || NULL);
  blk.add(40).writeU64(contextId || 0);
  return blk;
}

function callBlock(block, ret, argTypes, args) {
  const raw = block.add(16).readPointer().strip();
  const key = raw.toString() + '|' + ret + '|' + argTypes.join(',');
  let fn = invokeCache.get(key);
  if (fn === undefined) {
    fn = new NativeFunction(raw.sign(), ret, ['pointer'].concat(argTypes));
    if (invokeCache.size > 2048) invokeCache.clear();
    invokeCache.set(key, fn);
  }
  return fn.apply(null, [block].concat(args));
}

function blockInvokeModule(block) {
  try {
    return moduleNameFor(block.add(16).readPointer().strip());
  } catch (_) {
    return null;
  }
}

// xpc_dictionary_apply() collector: a single global block whose invoke
// pushes (key, value) pairs onto the calling thread's innermost collector.
// Collectors are per thread because NativeFunction calls release the JS
// lock, so hooks on other threads may decode messages concurrently.
const applyStacks = new Map();
let applyBlock = null;

function initApplyBlock() {
  const invoke = new NativeCallback(function (_block, key, value) {
    const stack = applyStacks.get(Process.getCurrentThreadId());
    const top = stack !== undefined ? stack[stack.length - 1] : undefined;
    if (top === undefined || top.items.length >= top.limit) return 0;
    top.items.push([readCString(key) || '', value]);
    return 1;
  }, 'bool', ['pointer', 'pointer', 'pointer']);
  keepAlive.push(invoke);
  applyBlock = makeGlobalBlock(invoke, 'B24@?0r*8@16', NULL, 0);
  keepAlive.push(applyBlock);
}

function dictionaryEntries(dict, limit) {
  const tid = Process.getCurrentThreadId();
  let stack = applyStacks.get(tid);
  if (stack === undefined) {
    stack = [];
    applyStacks.set(tid, stack);
  }
  const collector = { items: [], limit: limit };
  stack.push(collector);
  try {
    X.xpc_dictionary_apply(dict, applyBlock);
  } catch (e) {
    log('[!]', 'xpc_dictionary_apply failed: ' + e);
  } finally {
    stack.pop();
    if (stack.length === 0) applyStacks.delete(tid);
  }
  return collector.items;
}

// --- XPC decoding ---------------------------------------------------------------

function decodeXpc(obj, budget, depth) {
  if (budget.nodes <= 0 || depth > MAX_TREE_DEPTH) return { t: 'truncated' };
  budget.nodes -= 1;
  const type = xpcType(obj);
  try {
    switch (type) {
      case 'dictionary': {
        const entries = dictionaryEntries(obj, 512);
        return { t: 'dictionary', v: entries.map(([k, v]) => [k, decodeXpc(v, budget, depth + 1)]) };
      }
      case 'array': {
        const count = Math.min(Number(X.xpc_array_get_count(obj)), 256);
        const items = [];
        for (let i = 0; i < count; i++) items.push(decodeXpc(X.xpc_array_get_value(obj, i), budget, depth + 1));
        return { t: 'array', v: items };
      }
      case 'string':
        return { t: 'string', v: readCString(X.xpc_string_get_string_ptr(obj), MAX_STRING) };
      case 'int64':
        return { t: 'int64', v: X.xpc_int64_get_value(obj).toString() };
      case 'uint64':
        return { t: 'uint64', v: X.xpc_uint64_get_value(obj).toString() };
      case 'bool':
        return { t: 'bool', v: X.xpc_bool_get_value(obj) ? 'true' : 'false' };
      case 'double':
        return { t: 'double', v: String(X.xpc_double_get_value(obj)) };
      case 'date':
        return { t: 'date', v: new Date(X.xpc_date_get_value(obj).toNumber() / 1e6).toISOString() };
      case 'uuid':
        return { t: 'uuid', v: formatUuid(readBytes(X.xpc_uuid_get_bytes(obj), 16)) };
      case 'data':
        return decodeData(obj);
      case 'error':
        return { t: 'error', v: errorName(obj) || describeXpc(obj, 512) };
      case 'connection':
        return { t: 'connection', v: connectionLabel(obj) };
      case 'null':
        return { t: 'null', v: 'null' };
      default:
        return { t: type, v: describeXpc(obj, 256) };
    }
  } catch (e) {
    return { t: type, v: '<decode failed: ' + e + '>' };
  }
}

function decodeData(obj) {
  const length = Number(X.xpc_data_get_length(obj));
  const bytesPtr = X.xpc_data_get_bytes_ptr(obj);
  const scanned = readBytes(bytesPtr, Math.min(length, DATA_SCAN));
  const node = { t: 'data', len: length, hex: fmt.toHex(scanned, DATA_PREVIEW), bplist: fmt.detectBplist(scanned) };
  if (node.bplist !== null) {
    node.strings = fmt.extractStrings(scanned, 4, 64);
    if (node.bplist === 'bplist00' && length <= DATA_SCAN) node.b64 = fmt.toBase64(scanned);
  }
  return node;
}

function formatUuid(bytes) {
  const h = fmt.toHex(bytes);
  return [h.slice(0, 8), h.slice(8, 12), h.slice(12, 16), h.slice(16, 20), h.slice(20)].join('-').toUpperCase();
}

function describeXpc(obj, limit) {
  if (X.xpc_copy_description === null) return '';
  const p = X.xpc_copy_description(obj);
  if (p.isNull()) return '';
  try {
    return readCString(p, limit || MAX_DESCRIPTION) || '';
  } finally {
    if (LIBC.free) LIBC.free(p);
  }
}

// --- Connection metadata ----------------------------------------------------------

const connections = new Map();

function rememberConnection(conn, meta) {
  if (conn === null || conn.isNull()) return;
  if (connections.size > 4096) connections.delete(connections.keys().next().value);
  connections.set(conn.toString(), meta);
}

function connectionMeta(conn) {
  const meta = connections.get(conn.toString()) || {};
  let name = meta.name || null;
  if (!name && X.xpc_connection_get_name) {
    try { name = readCString(X.xpc_connection_get_name(conn)); } catch (_) {}
  }
  return {
    name: name,
    kind: meta.kind || (name ? 'named' : 'unknown'),
    listener: Boolean(meta.listener),
    privileged: Boolean(meta.privileged),
    listenerName: meta.listenerName || null,
  };
}

function processPath(pid) {
  if (!LIBC.proc_pidpath || pid <= 0) return null;
  const buf = Memory.alloc(4096);
  try {
    return LIBC.proc_pidpath(pid, buf, 4096) > 0 ? buf.readUtf8String() : null;
  } catch (_) {
    return null;
  }
}

const pathCache = new Map();
function peerInfo(conn) {
  const info = { pid: null, euid: null, path: null };
  try { info.pid = X.xpc_connection_get_pid(conn); } catch (_) {}
  try { info.euid = X.xpc_connection_get_euid(conn); } catch (_) {}
  if (info.pid > 0) {
    if (!pathCache.has(info.pid)) {
      if (pathCache.size > 1024) pathCache.clear();
      pathCache.set(info.pid, processPath(info.pid));
    }
    info.path = pathCache.get(info.pid);
  }
  return info;
}

function connectionLabel(conn) {
  const meta = connectionMeta(conn);
  const peer = peerInfo(conn);
  const parts = [];
  if (meta.name) parts.push(meta.name);
  if (peer.pid) parts.push('pid ' + peer.pid);
  if (peer.path) parts.push(peer.path);
  return parts.join(' ') || conn.toString();
}

function componentFor(meta, peer) {
  if (meta.name) return meta.name;
  if (meta.listenerName) return meta.listenerName;
  if (peer.path) return peer.path;
  if (peer.pid) return 'pid ' + peer.pid;
  return null;
}

// --- Decisions -------------------------------------------------------------------

const decisions = createDecisionCore({
  jsThreadId: JS_THREAD_ID,
  captureStack: captureStack,
});

// Sends an event to the host and, when it is interceptable, waits for the
// host decision. Returns {mode: 'forward'|'drop', mods: [...], eventId}.
function processEvent(ev, context) {
  return decisions.process(ev, context);
}

// --- XPC modifications --------------------------------------------------------------

function resolveParent(dict, path) {
  const parts = fmt.splitPath(path);
  if (parts.length === 0) return null;
  let current = dict;
  for (let i = 0; i < parts.length - 1; i++) {
    const keyPtr = toCString(parts[i]);
    let child = X.xpc_dictionary_get_value(current, keyPtr);
    if (child.isNull()) {
      log('[!]', 'Path segment "' + parts[i] + '" not found in ' + path);
      return null;
    }
    if (xpcType(child) !== 'dictionary') {
      log('[!]', 'Path segment "' + parts[i] + '" is not a dictionary in ' + path);
      return null;
    }
    current = child;
  }
  return [current, toCString(parts[parts.length - 1])];
}

function applyXpcMods(dict, mods) {
  if (!mods.length || dict === null || dict.isNull() || xpcType(dict) !== 'dictionary') return;
  for (const mod of mods) {
    try {
      const target = resolveParent(dict, mod.key);
      if (target === null) continue;
      const [parent, key] = target;
      if (mod.type === 'extra_rem') {
        X.xpc_dictionary_set_value(parent, key, NULL);
      } else if (mod.type === 'extra_add') {
        const type = fmt.normalizeValueType(mod.extraType);
        const val = String(mod.val);
        if (type === 'int64') X.xpc_dictionary_set_int64(parent, key, int64(val));
        else if (type === 'uint64') X.xpc_dictionary_set_uint64(parent, key, uint64(val));
        // Frida marshals 'bool' arguments from integers, not JS booleans.
        else if (type === 'bool') X.xpc_dictionary_set_bool(parent, key, (val.toLowerCase() === 'true' || val === '1') ? 1 : 0);
        else if (type === 'double') X.xpc_dictionary_set_double(parent, key, parseFloat(val));
        else if (type === 'data') {
          const bytes = fmt.parseHex(val);
          if (bytes === null) {
            log('[!]', 'Invalid hex for data value of ' + mod.key);
            continue;
          }
          const buf = Memory.alloc(Math.max(bytes.length, 1));
          buf.writeByteArray(Array.from(bytes));
          X.xpc_dictionary_set_data(parent, key, buf, bytes.length);
        } else {
          X.xpc_dictionary_set_string(parent, key, toCString(val));
        }
      }
    } catch (e) {
      log('[!]', 'Error applying ' + mod.type + ' on ' + mod.key + ': ' + e);
    }
  }
  log('[+]', 'Applied ' + mods.length + ' modification(s) to XPC message');
}

// --- XPC events ---------------------------------------------------------------------

const XPC_MESSAGE_MODS = ['extra_add', 'extra_rem'];
// threadId -> {selector, eventId} of the NSXPC call being serialized on it.
const sendContext = new Map();

function describeMessage(msg) {
  const tree = decodeXpc(msg, { nodes: MAX_TREE_NODES }, 0);
  const nsxpc = fmt.nsxpcInfo(tree);
  const extras = fmt.flattenTree(tree, 256);
  return {
    tree: tree,
    extras: extras,
    blobs: fmt.collectBlobs(tree, 16),
    nsxpc: nsxpc,
    // Only needed when the flattened view is incomplete; building it for every
    // message is expensive.
    description: '…' in extras ? describeXpc(msg, MAX_DESCRIPTION) : null,
  };
}

function xpcAttackSurface(direction, meta, peer, extra) {
  const surface = { platform: 'ios', direction: direction, serviceKind: meta.kind };
  if (meta.listener) surface.listener = true;
  if (meta.privileged) surface.privileged = true;
  if (peer.pid) surface.peerPid = peer.pid;
  if (peer.path) surface.peerPath = peer.path;
  return Object.assign(surface, extra || {});
}

function xpcMessageEvent(opts) {
  const meta = connectionMeta(opts.conn);
  const peer = peerInfo(opts.conn);
  const msgType = xpcType(opts.msg);
  const ipc = {
    kind: 'xpc',
    direction: opts.direction,
    connection: Object.assign({ address: opts.conn.toString() }, meta),
    peer: peer,
    messageType: msgType,
    expectsReply: Boolean(opts.expectsReply),
  };
  if (opts.correlation) ipc.correlation = opts.correlation;

  let extras = {};
  let action = null;
  let interceptable = opts.interceptable !== false;
  let mods = XPC_MESSAGE_MODS;

  if (msgType === 'dictionary') {
    const decoded = describeMessage(opts.msg);
    extras = decoded.extras;
    if (decoded.description) ipc.description = decoded.description;
    if (decoded.blobs.length) ipc.blobs = decoded.blobs;
    if (decoded.nsxpc) {
      ipc.nsxpc = decoded.nsxpc;
      const call = sendContext.get(Process.getCurrentThreadId());
      action = (call && call.selector) || decoded.nsxpc.selector;
      ipc.selectorSource = call && call.selector ? 'nsxpc' : (decoded.nsxpc.selector ? 'heuristic' : null);
      if (call && call.eventId) {
        // Already intercepted with decoded arguments at the NSXPC layer.
        ipc.nsxpcCall = call.eventId;
        interceptable = false;
      }
      // Incoming NSXPC payloads are intercepted (with decoded arguments) by
      // the exported-object hooks; at this layer they are observe-only.
      if (opts.direction !== 'outgoing') interceptable = false;
    }
  } else if (msgType === 'error') {
    action = errorName(opts.msg) || 'XPC_ERROR';
    ipc.description = describeXpc(opts.msg, 1024);
    interceptable = false;
    mods = [];
  } else if (msgType === 'connection') {
    const peerConn = peerInfo(opts.msg);
    action = 'new peer connection';
    ipc.newPeer = peerConn;
    extras = {
      'peer/pid': { type: 'int64', value: String(peerConn.pid) },
      'peer/euid': { type: 'uint64', value: String(peerConn.euid) },
    };
    if (peerConn.path) extras['peer/path'] = { type: 'string', value: peerConn.path };
    mods = [];
  } else {
    ipc.description = describeXpc(opts.msg, 1024);
    mods = [];
  }

  const surfaceExtra = {};
  if (msgType === 'connection') {
    surfaceExtra.exposure = 'listener';
    surfaceExtra.peerPid = ipc.newPeer.pid;
    if (ipc.newPeer.path) surfaceExtra.peerPath = ipc.newPeer.path;
  } else if (opts.direction === 'incoming' && (meta.kind === 'peer' || meta.listenerName)) {
    surfaceExtra.exposure = 'service';
  }

  return {
    className: opts.className,
    methodName: opts.methodName,
    component: componentFor(meta, peer),
    action: action,
    extras: extras,
    interceptable: interceptable,
    mods: interceptable ? mods : [],
    attackSurface: xpcAttackSurface(opts.direction, meta, peer, surfaceExtra),
    ipc: ipc,
  };
}

function handleXpcEvent(context, opts) {
  return withBusyThread(function () {
    try {
      const ev = xpcMessageEvent(opts);
      const result = processEvent(ev, context);
      if (result.mode === 'forward' && result.mods.length) applyXpcMods(opts.msg, result.mods);
      return result;
    } catch (e) {
      log('[!]', opts.methodName + ' handler failed: ' + e);
      return { mode: 'forward', mods: [] };
    }
  });
}

// Incoming events and replies are delivered through our wrapper blocks.
const wrapperContexts = new Map();
let wrapperCounter = 0;
let wrapperInvoke = null;

function wrapHandler(original, ctx) {
  const copy = LIBC.Block_copy(original);
  wrapperCounter += 1;
  const blk = makeGlobalBlock(wrapperInvoke, 'v16@?0@8', copy, wrapperCounter);
  ctx.block = blk;
  ctx.original = copy;
  ctx.module = blockInvokeModule(copy);
  wrapperContexts.set(wrapperCounter, ctx);
  return blk;
}

// Called after a handler's last event (a reply, or XPC_ERROR_CONNECTION_INVALID).
// Only our copy of the original block is released; the wrapper block itself
// stays allocated (see allocBlock) and turns into a no-op.
function retireWrapper(id) {
  const ctx = wrapperContexts.get(id);
  if (ctx === undefined) return;
  wrapperContexts.delete(id);
  setTimeout(function () {
    try { LIBC.Block_release(ctx.original); } catch (_) {}
  }, 10000);
}

function initWrapperInvoke() {
  wrapperInvoke = new NativeCallback(function (block, obj) {
    const id = block.add(40).readU64().toNumber();
    const original = block.add(32).readPointer();
    const ctx = wrapperContexts.get(id);
    if (ctx === undefined) {
      // Retired wrapper: the original copy may already be released. libxpc
      // does not deliver events after the final one, so there is nothing to do.
      return;
    }
    if (shouldPassthrough()) {
      callBlock(original, 'void', ['pointer'], [obj]);
      return;
    }
    const state = { delivered: false };
    try {
      deliverWrapped(this.context, id, ctx, original, obj, state);
    } catch (e) {
      log('[!]', 'XPC handler wrapper failed: ' + e);
      if (!state.delivered) callBlock(original, 'void', ['pointer'], [obj]);
    }
  }, 'void', ['pointer', 'pointer']);
  keepAlive.push(wrapperInvoke);
}

function deliverWrapped(context, id, ctx, original, obj, state) {
  const isReply = ctx.kind === 'reply';
  const result = handleXpcEvent(context, {
    conn: ctx.conn,
    msg: obj,
    direction: isReply ? 'reply' : 'incoming',
    methodName: isReply ? 'xpc_reply_handler' : 'xpc_event_handler',
    className: ctx.module || 'libxpc',
    correlation: ctx.correlation,
  });

  if (result.mode === 'drop') {
    if (xpcType(obj) === 'connection') {
      try { X.xpc_connection_cancel(obj); } catch (_) {}
    }
  } else {
    if (!isReply && xpcType(obj) === 'connection') {
      const listener = connectionMeta(ctx.conn);
      rememberConnection(obj, { kind: 'peer', listenerName: listener.name || listener.listenerName });
    }
    state.delivered = true;
    callBlock(original, 'void', ['pointer'], [obj]);
  }

  if (isReply || errorName(obj) === 'XPC_ERROR_CONNECTION_INVALID') retireWrapper(id);
}

function hookXpcCreation() {
  const specs = [
    ['xpc_connection_create', function (args) {
      const name = readCString(args[0]);
      return { name: name, kind: name ? 'service' : 'anonymous', listener: !name };
    }],
    ['xpc_connection_create_mach_service', function (args) {
      const flags = args[2].toUInt32();
      return { name: readCString(args[0]), kind: 'mach', listener: (flags & 1) !== 0, privileged: (flags & 2) !== 0 };
    }],
    ['xpc_connection_create_from_endpoint', function () {
      return { kind: 'endpoint' };
    }],
  ];
  for (const [name, describe] of specs) {
    const addr = findExport(name, LIBXPC);
    if (addr === null) continue;
    Interceptor.attach(addr, {
      onEnter(args) { this.meta = describe(args); },
      onLeave(retval) { rememberConnection(retval, this.meta); },
    });
  }
}

function hookXpc(entry) {
  const fn = entry.function;
  const addr = findExport(fn, LIBXPC);
  if (addr === null) {
    if (!entry.optional) throw new Error(fn + ' not found');
    log('[~]', 'Skipping ' + fn + ' (not available on this OS)');
    return false;
  }
  const intercept = entry.intercept !== false;
  const caller = function (ctx) { return moduleNameFor(ctx.returnAddress) || 'unknown'; };
  // An NSXPC call dropped at the NSXPC layer: swallow the message it sends.
  const nsxpcDropped = function () {
    const call = sendContext.get(Process.getCurrentThreadId());
    return call !== undefined && call.drop === true;
  };

  if (fn === 'xpc_connection_send_message' || fn === 'xpc_connection_send_notification') {
    const orig = new NativeFunction(addr, 'void', ['pointer', 'pointer']);
    const cb = new NativeCallback(function (conn, msg) {
      if (nsxpcDropped()) return;
      if (shouldPassthrough()) return orig(conn, msg);
      const r = handleXpcEvent(this.context, {
        conn: conn, msg: msg, direction: 'outgoing', methodName: fn,
        className: caller(this), interceptable: intercept,
      });
      if (r.mode !== 'drop') orig(conn, msg);
    }, 'void', ['pointer', 'pointer']);
    Interceptor.replace(addr, cb);
    keepAlive.push(cb);
  } else if (fn === 'xpc_connection_send_message_with_reply') {
    const orig = new NativeFunction(addr, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
    const cb = new NativeCallback(function (conn, msg, queue, handler) {
      if (nsxpcDropped()) return;
      if (shouldPassthrough()) return orig(conn, msg, queue, handler);
      const r = handleXpcEvent(this.context, {
        conn: conn, msg: msg, direction: 'outgoing', methodName: fn,
        className: caller(this), interceptable: intercept, expectsReply: true,
      });
      if (r.mode === 'drop') return;
      let replyHandler = handler;
      if (!handler.isNull() && xpcReady) {
        replyHandler = wrapHandler(handler, { kind: 'reply', conn: conn, correlation: r.eventId });
      }
      orig(conn, msg, queue, replyHandler);
    }, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);
    Interceptor.replace(addr, cb);
    keepAlive.push(cb);
  } else if (fn === 'xpc_connection_send_message_with_reply_sync') {
    const orig = new NativeFunction(addr, 'pointer', ['pointer', 'pointer']);
    const cb = new NativeCallback(function (conn, msg) {
      if (nsxpcDropped()) return XPC_CONST.interrupted || NULL;
      if (shouldPassthrough()) return orig(conn, msg);
      const module = caller(this);
      const r = handleXpcEvent(this.context, {
        conn: conn, msg: msg, direction: 'outgoing', methodName: fn,
        className: module, interceptable: intercept, expectsReply: true,
      });
      if (r.mode === 'drop') return XPC_CONST.interrupted || NULL;
      const reply = orig(conn, msg);
      const rr = handleXpcEvent(this.context, {
        conn: conn, msg: reply, direction: 'reply', methodName: fn + ' (reply)',
        className: module, interceptable: intercept, correlation: r.eventId,
      });
      if (rr.mode === 'drop') {
        X.xpc_release(reply);
        return XPC_CONST.interrupted || NULL;
      }
      return reply;
    }, 'pointer', ['pointer', 'pointer']);
    Interceptor.replace(addr, cb);
    keepAlive.push(cb);
  } else if (fn === 'xpc_connection_set_event_handler') {
    if (!xpcReady) throw new Error('block support unavailable (64-bit libxpc/libsystem_blocks required)');
    Interceptor.attach(addr, {
      onEnter(args) {
        if (args[1].isNull() || shouldPassthrough()) return;
        args[1] = wrapHandler(args[1], { kind: 'event', conn: args[0] });
      },
    });
  } else {
    throw new Error('unsupported xpc hook ' + fn);
  }
  return true;
}

// --- Objective-C helpers ----------------------------------------------------------

const hookedMethods = new Map();
const activeSelectors = new Set();

function objcAvailable() {
  try {
    return ObjC.available;
  } catch (_) {
    return false;
  }
}

function wrapObject(p) {
  if (p === null || p.isNull()) return null;
  try {
    return new ObjC.Object(p);
  } catch (_) {
    return null;
  }
}

function objcString(obj) {
  if (obj === null) return null;
  try {
    return obj.toString();
  } catch (_) {
    return null;
  }
}

function truncate(text, limit) {
  if (text === null || text === undefined) return text;
  const s = String(text);
  return s.length > limit ? s.slice(0, limit) + '…' : s;
}

function describeObjCArg(encoding, value) {
  const kind = fmt.objcTypeKind(encoding);
  if (kind === 'object') {
    const obj = wrapObject(value);
    if (obj === null) return { type: fmt.objcClassHint(encoding) || 'id', value: 'nil' };
    let className = 'id';
    try { className = obj.$className; } catch (_) {}
    if (className.indexOf('Block') !== -1) return { type: className, value: '<block>' };
    // -description on a proxy (e.g. an NSXPC remote object) may be forwarded
    // to another process; never call it from inside a hook.
    try {
      if (obj.isProxy()) return { type: className, value: '<proxy>' };
    } catch (_) {
      return { type: className, value: '<object>' };
    }
    try {
      if (obj.isKindOfClass_(ObjC.classes.NSData)) {
        const length = obj.length();
        const bytes = readBytes(obj.bytes(), Math.min(length, DATA_PREVIEW));
        return { type: className, value: length + ' bytes ' + fmt.toHex(bytes) };
      }
    } catch (_) {}
    return { type: className, value: truncate(objcString(obj), 2048) };
  }
  if (kind === 'block') return { type: 'block', value: value.isNull() ? 'nil' : '<block>' };
  if (kind === 'selector') return { type: 'SEL', value: value.isNull() ? 'nil' : ObjC.selectorAsString(value) };
  if (kind === 'cstring') return { type: 'char *', value: readCString(value, MAX_STRING) };
  if (kind === 'bool') return { type: 'bool', value: value ? 'true' : 'false' };
  if (kind === 'integer') return { type: 'int64', value: String(value) };
  if (kind === 'float') return { type: 'double', value: String(value) };
  if (kind === 'class') return { type: 'Class', value: value.isNull() ? 'nil' : String(new ObjC.Object(value)) };
  return { type: encoding, value: value === null || value === undefined ? '' : String(value) };
}

function methodEncodings(method) {
  try {
    return fmt.parseObjCTypes(ObjC.api.method_getTypeEncoding(method.handle).readCString());
  } catch (_) {
    return [];
  }
}

function defaultReturn(returnType) {
  if (returnType === 'void') return undefined;
  if (returnType === 'pointer') return NULL;
  if (Array.isArray(returnType)) return undefined;
  return 0;
}

function argumentExtras(encodings, args) {
  const extras = {};
  for (let i = 2; i < args.length; i++) {
    extras['arg' + (i - 2)] = describeObjCArg(encodings[i + 1], args[i]);
  }
  return extras;
}

// Converts a staged "+x (type) argN <value>" into a native value for an
// argument of the given ObjC type encoding.
function coerceArg(encoding, mod, current) {
  const kind = fmt.objcTypeKind(encoding);
  const type = fmt.normalizeValueType(mod.extraType) || 'string';
  const val = String(mod.val);
  if (kind === 'object') return makeObjCValue(type, val, current instanceof NativePointer ? wrapObject(current) : current);
  if (kind === 'bool') return (val.toLowerCase() === 'true' || val === '1') ? 1 : 0;
  if (kind === 'integer') return parseInt(val, val.indexOf('0x') === 0 ? 16 : 10);
  if (kind === 'float') return parseFloat(val);
  throw new Error('cannot modify arguments of type ' + encoding);
}

function argModIndex(mod) {
  const m = /^arg(\d+)$/.exec(mod.key || '');
  if (mod.type !== 'extra_add' || m === null) {
    log('[!]', 'Unsupported modification for Objective-C call: ' + mod.type + ' ' + (mod.key || ''));
    return -1;
  }
  return parseInt(m[1], 10);
}

function applyObjCArgMods(encodings, args, mods) {
  for (const mod of mods) {
    const n = argModIndex(mod);
    if (n < 0) continue;
    const index = n + 2;
    if (index >= args.length) {
      log('[!]', 'No argument ' + mod.key);
      continue;
    }
    try {
      args[index] = coerceArg(encodings[index + 1], mod, args[index]);
    } catch (e) {
      log('[!]', 'Error modifying ' + mod.key + ': ' + e);
    }
  }
}

function makeObjCValue(type, val, previous) {
  const C = ObjC.classes;
  let value;
  if (type === 'int64' || type === 'uint64') value = C.NSNumber.numberWithLongLong_(parseInt(val, 10));
  else if (type === 'double') value = C.NSNumber.numberWithDouble_(parseFloat(val));
  else if (type === 'bool') value = C.NSNumber.numberWithBool_(val.toLowerCase() === 'true' || val === '1');
  else if (type === 'data') {
    const bytes = fmt.parseHex(val);
    if (bytes === null) throw new Error('invalid hex');
    const buf = Memory.alloc(Math.max(bytes.length, 1));
    buf.writeByteArray(Array.from(bytes));
    value = C.NSData.dataWithBytes_length_(buf, bytes.length);
  } else if (previous !== null && previous.isKindOfClass_(C.NSURL)) {
    value = C.NSURL.URLWithString_(val);
  } else {
    value = C.NSString.stringWithString_(val);
  }
  keepTemp(value);
  return value.handle;
}

// Replaces an Objective-C method. `handler(original, args, info)` must return
// the method's return value; args = [self, _cmd, ...].
function hookObjCMethod(klass, methodName, handler) {
  const method = klass[methodName];
  if (method === undefined) return false;
  const key = method.handle.toString();
  if (hookedMethods.has(key)) return false;
  const original = method.implementation;
  const info = {
    className: klass.$className,
    selector: methodName.slice(2),
    returnType: method.returnType,
    encodings: methodEncodings(method),
  };
  const replacement = ObjC.implement(method, function () {
    const args = Array.prototype.slice.call(arguments);
    if (shouldPassthrough()) return original.apply(null, args);
    let called = false;
    const tracked = function () {
      called = true;
      return original.apply(null, arguments);
    };
    try {
      return handler.call(this, tracked, args, info);
    } catch (e) {
      log('[!]', info.className + ' ' + info.selector + ' hook failed: ' + e);
      return called ? defaultReturn(info.returnType) : original.apply(null, args);
    }
  });
  method.implementation = replacement;
  hookedMethods.set(key, { replacement: replacement, original: original });
  return true;
}

// Passive hook for observe-only (or argument-rewriting) Objective-C hooks:
// the original implementation stays in place, so there is no replacement
// signature to get wrong. Callbacks receive raw args ([self, _cmd, ...]).
const attachedMethods = new Set();

function attachObjCMethod(klass, methodName, callbacks) {
  const method = klass[methodName];
  if (method === undefined) return false;
  const key = method.handle.toString() + ' ' + methodName;
  if (attachedMethods.has(key)) return false;
  attachedMethods.add(key);
  const info = { className: klass.$className, selector: methodName.slice(2), encodings: methodEncodings(method) };
  const guarded = {};
  if (callbacks.onEnter) {
    guarded.onEnter = function (args) {
      this.ioxenSkip = shouldPassthrough();
      if (this.ioxenSkip) return;
      try {
        callbacks.onEnter.call(this, args, info);
      } catch (e) {
        log('[!]', info.className + ' ' + info.selector + ' hook failed: ' + e);
      }
    };
  }
  if (callbacks.onLeave) {
    guarded.onLeave = function (retval) {
      if (this.ioxenSkip) return;
      try {
        callbacks.onLeave.call(this, retval, info);
      } catch (e) {
        log('[!]', info.className + ' ' + info.selector + ' hook failed: ' + e);
      }
    };
  }
  Interceptor.attach(method.implementation, guarded);
  return true;
}

// Calls the original implementation while marking the selector as active on
// this thread, so nested calls of the same selector (e.g. an app delegate
// forwarding openURL to an SDK) are observed but not intercepted twice.
function callOriginal(original, args, selector) {
  const key = Process.getCurrentThreadId() + ' ' + selector;
  const nested = activeSelectors.has(key);
  activeSelectors.add(key);
  try {
    return original.apply(null, args);
  } finally {
    if (!nested) activeSelectors.delete(key);
  }
}

function isNestedSelector(selector) {
  return activeSelectors.has(Process.getCurrentThreadId() + ' ' + selector);
}

function runtimeClassName(selfPtr, fallback) {
  const obj = wrapObject(selfPtr);
  try {
    return obj !== null ? obj.$className : fallback;
  } catch (_) {
    return fallback;
  }
}

// Generic interceptable Objective-C call event.
function objcCallEvent(context, original, args, info, extra) {
  const ev = Object.assign({
    className: runtimeClassName(args[0], info.className),
    methodName: (info.isClassMethod ? '+' : '-') + '[' + info.className + ' ' + info.selector + ']',
    action: info.selector,
    extras: argumentExtras(info.encodings, args),
    interceptable: !isNestedSelector(info.selector),
    mods: ['extra_add'],
    attackSurface: { platform: 'ios', direction: 'incoming' },
    ipc: { kind: 'objc', direction: 'incoming', selector: info.selector, receiverClass: info.className },
  }, extra || {});
  const r = withBusyThread(function () { return processEvent(ev, context); });
  if (r.mode === 'drop') {
    if (Array.isArray(info.returnType)) {
      log('[~]', 'Cannot drop ' + info.selector + ' (struct return); forwarding');
    } else {
      return { dropped: true, value: defaultReturn(info.returnType) };
    }
  }
  if (r.mods.length) withBusyThread(function () { applyObjCArgMods(info.encodings, args, r.mods); });
  return { dropped: false, value: callOriginal(original, args, info.selector) };
}

// One shared resolver: it caches the class list, so later patterns do not
// rescan every class while a spawned app waits to be resumed.
let objcResolver = null;

function resolveObjCPattern(pattern) {
  const out = [];
  try {
    if (objcResolver === null) objcResolver = new ApiResolver('objc');
    const resolver = objcResolver;
    for (const match of resolver.enumerateMatches(pattern)) {
      const m = /^([+-])\[(\S+) (.+)\]$/.exec(match.name);
      if (m !== null) out.push({ isClassMethod: m[1] === '+', className: m[2], selector: m[3] });
    }
  } catch (e) {
    log('[!]', 'ObjC resolver failed for ' + pattern + ': ' + e);
  }
  return out;
}

function hookObjCTarget(target, handler) {
  const klass = ObjC.classes[target.className];
  if (klass === undefined) return false;
  const name = (target.isClassMethod ? '+ ' : '- ') + target.selector;
  return hookObjCMethod(klass, name, function (original, args, info) {
    info.isClassMethod = target.isClassMethod;
    return handler.call(this, original, args, info);
  });
}

// --- NSXPC -----------------------------------------------------------------------

const nsxpcConnections = new Map();
const nsxpcListeners = new Map();
const reportedInterfaces = new Set();

function nsxpcConnectionName(conn) {
  if (conn === null) return null;
  const known = nsxpcConnections.get(conn.handle.toString());
  if (known && known.name) return known.name;
  try {
    const name = conn.serviceName();
    if (name !== null) return name.toString();
  } catch (_) {}
  return null;
}

function protocolSummaryObject(iface) {
  if (iface === null) return null;
  const protoPtr = iface.protocol();
  return new ObjC.Protocol(protoPtr.handle ? protoPtr.handle : protoPtr);
}

function protocolSummary(iface) {
  if (iface === null) return null;
  try {
    const protoPtr = iface.protocol();
    const proto = new ObjC.Protocol(protoPtr.handle ? protoPtr.handle : protoPtr);
    return {
      name: proto.name,
      methods: Object.keys(proto.methods).filter(n => n.indexOf('- ') === 0).map(n => n.slice(2)).sort(),
    };
  } catch (e) {
    return { name: objcString(iface), methods: [] };
  }
}

function connectionPeer(conn) {
  const peer = { pid: null, euid: null, path: null };
  try { peer.pid = conn.processIdentifier(); } catch (_) {}
  try { peer.euid = conn.effectiveUserIdentifier(); } catch (_) {}
  if (peer.pid > 0) peer.path = processPath(peer.pid);
  return peer;
}

function hookNSXPCConnections() {
  const C = ObjC.classes.NSXPCConnection;
  if (C === undefined) return false;

  const initHook = function (kind) {
    return {
      onEnter(args, info) {
        this.name = info.selector === 'initWithListenerEndpoint:' ? null : objcString(wrapObject(args[2]));
        this.options = info.selector === 'initWithMachServiceName:options:' ? args[3].toUInt32() : 0;
        this.selector = info.selector;
      },
      onLeave(retval) {
        if (retval.isNull()) return;
        const name = this.name;
        const options = this.options;
        nsxpcConnections.set(retval.toString(), { name: name, kind: kind, options: options });
        withBusyThread(function () {
          processEvent({
            className: 'NSXPCConnection',
            methodName: '-[NSXPCConnection ' + this.selector + ']',
            component: name,
            action: 'connect',
            extras: options ? { options: { type: 'uint64', value: '0x' + options.toString(16) } } : {},
            interceptable: false,
            attackSurface: { platform: 'ios', direction: 'outgoing', serviceKind: kind, privileged: (options & 0x1000) !== 0 },
            ipc: { kind: 'nsxpc_connection', direction: 'outgoing', service: name, serviceKind: kind, options: options },
          }, this.context);
        }.bind(this));
      },
    };
  };
  attachObjCMethod(C, '- initWithMachServiceName:options:', initHook('mach'));
  attachObjCMethod(C, '- initWithServiceName:', initHook('service'));
  attachObjCMethod(C, '- initWithListenerEndpoint:', initHook('endpoint'));

  const resumeHook = {
    onEnter(args) {
      const context = this.context;
      withBusyThread(function () { reportInterfaces(context, wrapObject(args[0])); });
    },
  };
  attachObjCMethod(C, '- resume', resumeHook);
  attachObjCMethod(C, '- activate', resumeHook);

  hookNSXPCSends(C);
  return true;
}

// --- NSXPC payload decoding ---------------------------------------------------------
//
// NSXPC serializes calls into a private, undocumented bplist16 blob, so the
// agent decodes them where Foundation still holds real objects:
//
//   * outgoing calls: the NSInvocation (or argument array) handed to the
//     private -[NSXPCConnection _send...] methods, before serialization;
//   * replies: the reply block, which NSXPC invokes with decoded objects;
//   * incoming calls: the exported-object hooks (see hookExportedObject).
//
// Each becomes an interceptable event whose arguments can be replaced. The
// raw libxpc message produced by an outgoing call is linked to it and
// observed only.

function readArgBuffer(buf, encoding) {
  const layout = fmt.scalarLayout(encoding);
  if (layout === null) return buf.readPointer();
  return buf['read' + layout[1]]();
}

function writeArgBuffer(buf, encoding, value) {
  const layout = fmt.scalarLayout(encoding);
  if (layout === null) buf.writePointer(value);
  else if (layout[1] === 'Float' || layout[1] === 'Double') buf['write' + layout[1]](value);
  else if (layout[1] === 'S64') buf.writeS64(int64(String(value)));
  else if (layout[1] === 'U64') buf.writeU64(uint64(String(value)));
  else buf['write' + layout[1]](value);
}

function protocolArgTypes(conn, selector) {
  try {
    const proto = protocolSummaryObject(conn.remoteObjectInterface());
    const desc = proto !== null ? proto.methods['- ' + selector] : undefined;
    if (desc !== undefined) return fmt.parseObjCTypes(desc.types).slice(3);
  } catch (_) {}
  return null;
}

// Returns {selector, args: [{encoding, get(), set(v)}]} or null. Only uses
// public API (NSInvocation / NSMethodSignature) or arguments whose types were
// validated against the method's runtime encoding.
function decodeNSXPCSend(layout, args, conn) {
  if (layout.kind === 'invocation') {
    const inv = wrapObject(args[layout.invocation]);
    if (inv === null || !inv.isKindOfClass_(ObjC.classes.NSInvocation)) {
      // Argument-array fast path: its layout is private, so only the
      // (validated) selector is reported.
      if (layout.selector < 0 || args[layout.selector].isNull()) return null;
      return { selector: ObjC.selectorAsString(args[layout.selector]), args: [] };
    }
    const sig = inv.methodSignature();
    const count = Math.max(0, Number(sig.numberOfArguments()) - 2);
    const decoded = [];
    for (let i = 0; i < count; i++) {
      const encoding = String(sig.getArgumentTypeAtIndex_(i + 2));
      const size = fmt.scalarLayout(encoding) !== null || fmt.objcTypeKind(encoding) !== 'struct' ? 16 : 0;
      if (size === 0) {
        decoded.push({ encoding: encoding, get() { return NULL; }, set() { throw new Error('struct arguments are not supported'); }, opaque: true });
        continue;
      }
      const buf = Memory.alloc(size);
      decoded.push({
        encoding: encoding,
        get() { inv.getArgument_atIndex_(buf, i + 2); return readArgBuffer(buf, encoding); },
        set(value) { writeArgBuffer(buf, encoding, value); inv.setArgument_atIndex_(buf, i + 2); },
      });
    }
    return { selector: ObjC.selectorAsString(inv.selector()), args: decoded };
  }
  const selector = ObjC.selectorAsString(args[layout.selector]);
  const types = protocolArgTypes(conn, selector) || [];
  return {
    selector: selector,
    args: layout.values.map(function (index, i) {
      return {
        encoding: types[i] || '@',
        get() { return args[index]; },
        set(value) { args[index] = value; },
      };
    }),
  };
}

let decodeReplies = false;

function hookNSXPCSends(C) {
  const names = C.$ownMethods.filter(n => /^- _send(Invocation|Selector):/.test(n));
  let count = 0;
  for (const name of names) {
    const layout = fmt.nsxpcSendLayout(name.slice(2));
    if (layout === null) continue;
    const method = C[name];
    if (method === undefined) continue;
    if (!fmt.validateSendLayout(layout, methodEncodings(method))) {
      log('[~]', 'Not decoding ' + name + ': unexpected type encoding');
      continue;
    }
    try {
      if (attachObjCMethod(C, name, {
        onEnter(args) {
          this.tid = Process.getCurrentThreadId();
          // The send variants call each other; only the outermost one is reported.
          if (sendContext.has(this.tid)) return;
          this.tracked = true;
          sendContext.set(this.tid, beginNSXPCSend(this.context, args, layout));
        },
        onLeave() {
          if (this.tracked) sendContext.delete(this.tid);
        },
      })) count += 1;
    } catch (e) {
      log('[~]', 'NSXPC decoding unavailable for ' + name + ': ' + e);
    }
  }
  if (count === 0) log('[~]', 'No NSXPC send methods recognised; outgoing NSXPC calls are not decoded');
}

// Reports an outgoing NSXPC call and returns the send context consumed by
// the libxpc send hooks: {selector, eventId, drop}.
function beginNSXPCSend(context, args, layout) {
  const conn = wrapObject(args[0]);
  const prepared = withBusyThread(function () {
    let call = null;
    try {
      call = decodeNSXPCSend(layout, args, conn);
    } catch (e) {
      log('[~]', 'NSXPC call could not be decoded: ' + e);
    }
    if (call === null) return null;
    const service = nsxpcConnectionName(conn);
    const peer = conn !== null ? connectionPeer(conn) : { pid: null, path: null };
    let protocol = null;
    try { protocol = protocolSummary(conn.remoteObjectInterface()); } catch (_) {}
    const extras = {};
    call.args.forEach(function (arg, i) {
      if (arg.opaque) {
        extras['arg' + i] = { type: arg.encoding, value: '<struct>' };
        return;
      }
      try { extras['arg' + i] = describeObjCArg(arg.encoding, arg.get()); } catch (e) { extras['arg' + i] = { type: arg.encoding, value: '<unreadable: ' + e + '>' }; }
    });
    return {
      call: call,
      service: service,
      ev: {
        className: 'NSXPCConnection',
        methodName: '-[' + (protocol ? protocol.name : 'NSXPCRemoteObjectProxy') + ' ' + call.selector + ']',
        component: service || (peer.path || (peer.pid ? 'pid ' + peer.pid : null)),
        action: call.selector,
        extras: extras,
        interceptable: true,
        mods: call.args.length ? ['extra_add'] : [],
        attackSurface: { platform: 'ios', direction: 'outgoing', peerPid: peer.pid, peerPath: peer.path },
        ipc: { kind: 'nsxpc_call', direction: 'outgoing', protocol: protocol ? protocol.name : null, selector: call.selector, service: service, peer: peer },
      },
    };
  });
  if (prepared === null) return { selector: null, eventId: null, drop: false };

  const r = withBusyThread(function () { return processEvent(prepared.ev, context); });
  if (r.mode === 'drop') {
    // The libxpc send hooks skip the message this call produces.
    return { selector: prepared.call.selector, eventId: r.eventId, drop: true };
  }
  withBusyThread(function () {
    for (const mod of r.mods) {
      const n = argModIndex(mod);
      if (n < 0) continue;
      const arg = prepared.call.args[n];
      if (arg === undefined || arg.opaque) {
        log('[!]', 'Cannot modify ' + mod.key);
        continue;
      }
      try {
        arg.set(coerceArg(arg.encoding, mod, arg.get()));
      } catch (e) {
        log('[!]', 'Error modifying ' + mod.key + ': ' + e);
      }
    }
    if (!decodeReplies) return;
    prepared.call.args.forEach(function (arg) {
      if (arg.opaque || fmt.objcTypeKind(arg.encoding) !== 'block') return;
      const blk = arg.get();
      if (blk.isNull()) return;
      const wrapped = wrapReplyBlock(blk, {
        selector: prepared.call.selector,
        service: prepared.service,
        protocol: prepared.ev.ipc.protocol,
        correlation: r.eventId,
      });
      if (wrapped !== null) arg.set(wrapped);
    });
  });
  return { selector: prepared.call.selector, eventId: r.eventId, drop: false };
}

const replyBlocks = new Map();
let replyCounter = 0;

function describeBlockArg(encoding, value) {
  if (value instanceof ObjC.Object) return describeObjCArg('@', value.handle);
  if (value === null || value === undefined) return { type: fmt.objcClassHint(encoding) || 'id', value: 'nil' };
  if (typeof value === 'boolean') return { type: 'bool', value: value ? 'true' : 'false' };
  return describeObjCArg(encoding, value);
}

// Replaces an NSXPC reply block with one that reports the decoded reply and
// then calls the original. Returns the new block's handle, or null.
function wrapReplyBlock(blockPtr, meta) {
  const copy = LIBC.Block_copy(blockPtr);
  let original;
  let originalImpl;
  try {
    original = new ObjC.Block(copy);
    originalImpl = original.implementation;
  } catch (e) {
    LIBC.Block_release(copy);
    log('[~]', 'Reply of ' + meta.selector + ' not decoded (block has no signature)');
    return null;
  }
  const encodings = fmt.parseObjCTypes(original.types).slice(2);
  replyCounter += 1;
  const id = replyCounter;
  const wrapper = new ObjC.Block({
    types: original.types,
    implementation: function () {
      const values = Array.prototype.slice.call(arguments);
      if (shouldPassthrough()) return originalImpl.apply(null, values);
      let delivered = false;
      try {
        const extras = {};
        values.forEach(function (v, i) { extras['arg' + i] = describeBlockArg(encodings[i], v); });
        const r = withBusyThread(function () {
          return processEvent({
            className: 'NSXPCConnection',
            methodName: 'reply ' + meta.selector,
            component: meta.service,
            action: meta.selector,
            extras: extras,
            interceptable: true,
            mods: ['extra_add'],
            attackSurface: { platform: 'ios', direction: 'reply' },
            ipc: { kind: 'nsxpc_reply', direction: 'reply', protocol: meta.protocol, selector: meta.selector, service: meta.service, correlation: meta.correlation },
          }, undefined);
        });
        if (r.mode === 'drop') return undefined;
        withBusyThread(function () {
          for (const mod of r.mods) {
            const n = argModIndex(mod);
            if (n < 0 || n >= values.length) continue;
            try {
              const current = values[n] instanceof ObjC.Object ? values[n].handle : values[n];
              values[n] = coerceArg(encodings[n], mod, current);
            } catch (e) {
              log('[!]', 'Error modifying reply ' + mod.key + ': ' + e);
            }
          }
        });
        delivered = true;
        return originalImpl.apply(null, values);
      } catch (e) {
        log('[!]', 'NSXPC reply hook failed: ' + e);
        if (!delivered) return originalImpl.apply(null, values);
        return undefined;
      } finally {
        // The wrapper block stays alive for good: NSInvocation and NSXPC may
        // still release it later. Only our copy of the original is released.
        const entry = replyBlocks.get(id);
        if (entry !== undefined && !entry.released) {
          entry.released = true;
          setTimeout(function () { LIBC.Block_release(entry.copy); }, 10000);
        }
      }
    },
  });
  replyBlocks.set(id, { wrapper: wrapper, original: original, copy: copy });
  return wrapper.handle;
}

function reportInterfaces(context, conn) {
  if (conn === null) return;
  const key = conn.handle.toString();
  if (reportedInterfaces.has(key)) return;
  let exported = null;
  let remote = null;
  let exportedObject = null;
  try { exported = protocolSummary(conn.exportedInterface()); } catch (_) {}
  try { remote = protocolSummary(conn.remoteObjectInterface()); } catch (_) {}
  try { exportedObject = conn.exportedObject(); } catch (_) {}
  if (exported === null && remote === null) return;
  reportedInterfaces.add(key);

  const name = nsxpcConnectionName(conn);
  const peer = connectionPeer(conn);
  const extras = {};
  if (exported) {
    extras['exported/protocol'] = { type: 'protocol', value: exported.name };
    exported.methods.forEach((m, i) => { extras['exported/methods[' + i + ']'] = { type: 'selector', value: m }; });
  }
  if (remote) {
    extras['remote/protocol'] = { type: 'protocol', value: remote.name };
    remote.methods.forEach((m, i) => { extras['remote/methods[' + i + ']'] = { type: 'selector', value: m }; });
  }
  if (exportedObject !== null) extras['exported/object'] = { type: 'class', value: exportedObject.$className };

  processEvent({
    className: exportedObject !== null ? exportedObject.$className : 'NSXPCConnection',
    methodName: '-[NSXPCConnection resume]',
    component: name || (peer.path || (peer.pid ? 'pid ' + peer.pid : null)),
    action: 'interface',
    extras: extras,
    interceptable: false,
    attackSurface: { platform: 'ios', direction: exported ? 'incoming' : 'outgoing', exposure: exported ? 'exported_interface' : undefined },
    ipc: { kind: 'nsxpc_interface', direction: exported ? 'incoming' : 'outgoing', service: name, peer: peer, exported: exported, remote: remote },
  }, context);

  if (exported !== null && exportedObject !== null) hookExportedObject(exportedObject, exported, name);
}

function hookExportedObject(obj, iface, serviceName) {
  for (const selector of iface.methods) {
    const klass = obj.$class;
    hookObjCMethod(klass, '- ' + selector, function (original, args, info) {
      const conn = currentNSXPCConnection();
      const peer = conn !== null ? connectionPeer(conn) : { pid: null, path: null };
      const service = (conn !== null ? nsxpcConnectionName(conn) : null) || serviceName;
      return objcCallEvent(this.context, original, args, info, {
        methodName: '-[' + info.className + ' ' + info.selector + ']',
        component: service || iface.name,
        attackSurface: { platform: 'ios', direction: 'incoming', exposure: 'exported_method', peerPid: peer.pid, peerPath: peer.path },
        ipc: { kind: 'nsxpc_call', direction: 'incoming', protocol: iface.name, selector: info.selector, service: service, peer: peer },
      }).value;
    });
  }
}

function currentNSXPCConnection() {
  try {
    return ObjC.classes.NSXPCConnection.currentConnection();
  } catch (_) {
    return null;
  }
}

function hookNSXPCListeners() {
  const L = ObjC.classes.NSXPCListener;
  if (L === undefined) return false;

  attachObjCMethod(L, '- initWithMachServiceName:', {
    onEnter(args) { this.name = objcString(wrapObject(args[2])); },
    onLeave(retval) {
      if (!retval.isNull()) nsxpcListeners.set(retval.toString(), { name: this.name, kind: 'mach' });
    },
  });
  const classFactory = function (kind) {
    return {
      onLeave(retval) {
        if (!retval.isNull()) nsxpcListeners.set(retval.toString(), { name: null, kind: kind });
      },
    };
  };
  attachObjCMethod(L, '+ serviceListener', classFactory('service'));
  attachObjCMethod(L, '+ anonymousListener', classFactory('anonymous'));
  attachObjCMethod(L, '- setDelegate:', {
    onEnter(args) {
      const delegate = wrapObject(args[2]);
      if (delegate !== null) hookAcceptDelegate(delegate.$className);
    },
  });

  for (const target of resolveObjCPattern('-[* listener:shouldAcceptNewConnection:]')) {
    hookAcceptDelegate(target.className);
  }
  return true;
}

function hookAcceptDelegate(className) {
  const klass = ObjC.classes[className];
  if (klass === undefined) return;
  hookObjCMethod(klass, '- listener:shouldAcceptNewConnection:', function (original, args, info) {
    const result = withBusyThread(function () {
      const listener = nsxpcListeners.get(args[2].toString()) || { name: null, kind: 'unknown' };
      const conn = wrapObject(args[3]);
      const peer = conn !== null ? connectionPeer(conn) : { pid: null, euid: null, path: null };
      const extras = {
        'peer/pid': { type: 'int64', value: String(peer.pid) },
        'peer/euid': { type: 'uint64', value: String(peer.euid) },
      };
      if (peer.path) extras['peer/path'] = { type: 'string', value: peer.path };
      return processEvent({
        className: runtimeClassName(args[0], className),
        methodName: '-[' + className + ' listener:shouldAcceptNewConnection:]',
        component: listener.name || listener.kind + ' listener',
        action: 'accept connection',
        extras: extras,
        interceptable: true,
        mods: [],
        attackSurface: { platform: 'ios', direction: 'incoming', exposure: 'listener', serviceKind: listener.kind, peerPid: peer.pid, peerPath: peer.path },
        ipc: { kind: 'nsxpc_accept', direction: 'incoming', service: listener.name, serviceKind: listener.kind, peer: peer },
      }, this.context);
    }.bind(this));
    if (result.mode === 'drop') {
      log('[+]', 'Rejected NSXPC connection (dropped)');
      return 0;
    }
    const accepted = callOriginal(original, args, info.selector);
    const conn = wrapObject(args[3]);
    if (accepted && conn !== null) {
      const listener = nsxpcListeners.get(args[2].toString());
      nsxpcConnections.set(conn.handle.toString(), { name: listener ? listener.name : null, kind: 'peer' });
    }
    return accepted;
  });
}

// --- URL schemes / universal links ---------------------------------------------------

let declaredSchemes = null;

function getDeclaredSchemes() {
  if (declaredSchemes !== null) return declaredSchemes;
  declaredSchemes = new Set();
  try {
    const types = ObjC.classes.NSBundle.mainBundle().objectForInfoDictionaryKey_('CFBundleURLTypes');
    const list = objcToJs(types, 4) || [];
    for (const t of list) {
      for (const s of (t && t.CFBundleURLSchemes) || []) declaredSchemes.add(String(s).toLowerCase());
    }
  } catch (_) {}
  return declaredSchemes;
}

function urlSurface(direction, url, extra) {
  const surface = Object.assign({ platform: 'ios', direction: direction }, extra || {});
  if (url && direction === 'incoming') {
    const scheme = String(url).split(':')[0].toLowerCase();
    if (scheme === 'http' || scheme === 'https') surface.exposure = surface.exposure || 'universal_link';
    else surface.exposure = getDeclaredSchemes().has(scheme) ? 'declared_scheme' : 'url_scheme';
  }
  return surface;
}

function optionsExtras(options, prefix) {
  const extras = {};
  const dict = objcToJs(wrapObject(options), 2);
  if (dict && typeof dict === 'object') {
    for (const key of Object.keys(dict)) {
      const value = dict[key];
      extras[prefix + key] = typeof value === 'string'
        ? { type: 'string', value: truncate(value, 1024) }
        : { type: 'option', value: truncate(JSON.stringify(value), 1024) };
    }
  }
  return extras;
}

function urlEvent(context, original, args, info, spec) {
  const urlObj = spec.urlIndex !== undefined ? wrapObject(args[spec.urlIndex]) : null;
  const url = spec.url !== undefined ? spec.url : objcString(urlObj);
  const extras = Object.assign({}, spec.extras || {});
  const ev = {
    className: runtimeClassName(args[0], info.className),
    methodName: (info.isClassMethod ? '+' : '-') + '[' + info.className + ' ' + info.selector + ']',
    action: spec.action,
    data: url,
    component: spec.component || null,
    extras: extras,
    interceptable: spec.interceptable !== false && !isNestedSelector(info.selector),
    mods: spec.urlIndex !== undefined || spec.setUrl ? ['data'] : [],
    attackSurface: urlSurface(spec.direction, url, spec.surface),
    ipc: { kind: 'url', direction: spec.direction, url: url, selector: info.selector },
  };
  const r = withBusyThread(function () { return processEvent(ev, context); });
  if (r.mode === 'drop') {
    if (spec.onDrop) return spec.onDrop();
    return defaultReturn(info.returnType);
  }
  for (const mod of r.mods) {
    if (mod.type !== 'data') continue;
    withBusyThread(function () {
      const newUrl = ObjC.classes.NSURL.URLWithString_(String(mod.val));
      if (newUrl === null || newUrl.handle.isNull()) {
        log('[!]', 'Invalid URL: ' + mod.val);
        return;
      }
      keepTemp(newUrl);
      if (spec.setUrl) spec.setUrl(newUrl);
      else args[spec.urlIndex] = newUrl.handle;
      log('[+]', 'URL replaced with ' + mod.val);
    });
  }
  return callOriginal(original, args, info.selector);
}

function hookUrlIncoming() {
  const handlers = [
    ['-[* application:openURL:options:]', function (original, args, info) {
      const extras = optionsExtras(args[4], 'options/');
      const source = extras['options/UIApplicationOpenURLOptionsSourceApplicationKey'];
      return urlEvent(this.context, original, args, info, {
        direction: 'incoming', action: 'openURL', urlIndex: 3, extras: extras,
        component: source ? source.value : null,
      });
    }],
    ['-[* application:openURL:sourceApplication:annotation:]', function (original, args, info) {
      const source = objcString(wrapObject(args[4]));
      return urlEvent(this.context, original, args, info, {
        direction: 'incoming', action: 'openURL', urlIndex: 3, component: source,
        extras: source ? { sourceApplication: { type: 'string', value: source } } : {},
      });
    }],
    ['-[* application:handleOpenURL:]', function (original, args, info) {
      return urlEvent(this.context, original, args, info, { direction: 'incoming', action: 'handleOpenURL', urlIndex: 3 });
    }],
    ['-[* application:continueUserActivity:restorationHandler:]', function (original, args, info) {
      return userActivityEvent(this.context, original, args, info, 3);
    }],
    ['-[* scene:continueUserActivity:]', function (original, args, info) {
      return userActivityEvent(this.context, original, args, info, 3);
    }],
    ['-[* scene:openURLContexts:]', function (original, args, info) {
      const contexts = urlContexts(wrapObject(args[3]));
      return urlEvent(this.context, original, args, info, {
        direction: 'incoming', action: 'openURLContexts', url: contexts.urls[0] || null,
        component: contexts.source, extras: contexts.extras,
      });
    }],
    ['-[* scene:willConnectToSession:options:]', function (original, args, info) {
      const options = wrapObject(args[4]);
      let contexts = { urls: [], extras: {}, source: null };
      let activity = null;
      try { contexts = urlContexts(options.URLContexts()); } catch (_) {}
      try {
        const acts = options.userActivities().allObjects();
        if (acts.count() > 0) activity = acts.objectAtIndex_(0);
      } catch (_) {}
      if (!contexts.urls.length && activity === null) return original.apply(null, args);
      const extras = contexts.extras;
      let url = contexts.urls[0] || null;
      if (activity !== null) {
        extras['userActivity/type'] = { type: 'string', value: objcString(activity.activityType()) };
        try { url = url || objcString(activity.webpageURL()); } catch (_) {}
      }
      return urlEvent(this.context, original, args, info, {
        direction: 'incoming', action: 'cold launch', url: url, component: contexts.source,
        extras: extras, interceptable: false,
      });
    }],
  ];

  let count = 0;
  for (const [pattern, handler] of handlers) {
    for (const target of resolveObjCPattern(pattern)) {
      if (hookObjCTarget(target, handler)) count += 1;
    }
  }
  return count;
}

function urlContexts(set) {
  const out = { urls: [], extras: {}, source: null };
  if (set === null) return out;
  try {
    const items = set.allObjects();
    for (let i = 0; i < items.count(); i++) {
      const ctx = items.objectAtIndex_(i);
      const url = objcString(ctx.URL());
      out.urls.push(url);
      out.extras['urls[' + i + ']'] = { type: 'url', value: url };
      try {
        const source = objcString(ctx.options().sourceApplication());
        if (source) {
          out.extras['urls[' + i + ']/sourceApplication'] = { type: 'string', value: source };
          out.source = out.source || source;
        }
      } catch (_) {}
    }
  } catch (_) {}
  return out;
}

function userActivityEvent(context, original, args, info, index) {
  const activity = wrapObject(args[index]);
  let url = null;
  const extras = {};
  if (activity !== null) {
    try { url = objcString(activity.webpageURL()); } catch (_) {}
    try { extras.activityType = { type: 'string', value: objcString(activity.activityType()) }; } catch (_) {}
    try {
      const userInfo = objcToJs(activity.userInfo(), 3);
      if (userInfo) {
        for (const key of Object.keys(userInfo)) {
          extras['userInfo/' + key] = { type: 'option', value: truncate(JSON.stringify(userInfo[key]), 1024) };
        }
      }
    } catch (_) {}
  }
  return urlEvent(context, original, args, info, {
    direction: 'incoming', action: 'continueUserActivity', url: url, extras: extras,
    setUrl: activity !== null ? function (newUrl) { activity.setWebpageURL_(newUrl); } : undefined,
    surface: { exposure: 'universal_link' },
  });
}

function hookUrlOutgoing() {
  const A = ObjC.classes.UIApplication;
  let count = 0;
  if (A !== undefined) {
    const openWithOptions = function (original, args, info) {
      const completion = args[4];
      return urlEvent(this.context, original, args, info, {
        direction: 'outgoing', action: 'openURL', urlIndex: 2, extras: optionsExtras(args[3], 'options/'),
        onDrop: function () {
          if (!completion.isNull()) {
            try { new ObjC.Block(completion).implementation(0); } catch (_) {}
          }
        },
      });
    };
    if (hookObjCMethod(A, '- openURL:options:completionHandler:', openWithOptions)) count += 1;
    if (hookObjCMethod(A, '- openURL:', function (original, args, info) {
      return urlEvent(this.context, original, args, info, { direction: 'outgoing', action: 'openURL', urlIndex: 2 });
    })) count += 1;
    if (hookObjCMethod(A, '- canOpenURL:', function (original, args, info) {
      return urlEvent(this.context, original, args, info, {
        direction: 'outgoing', action: 'canOpenURL', urlIndex: 2, interceptable: false,
        surface: { exposure: 'scheme_query' },
      });
    })) count += 1;
  }
  const E = ObjC.classes.NSExtensionContext;
  if (E !== undefined && hookObjCMethod(E, '- openURL:completionHandler:', function (original, args, info) {
    return urlEvent(this.context, original, args, info, { direction: 'outgoing', action: 'openURL', urlIndex: 2 });
  })) count += 1;
  return count;
}

// --- Web views ------------------------------------------------------------------------
//
// WKWebView / UIWebView / JavaScriptCore: the JavaScript <-> native bridge,
// injected scripts, page loads, navigation decisions, custom URL scheme
// handlers inside web views, in-app browsers and OAuth sessions.

function objString(p) {
  return objcString(wrapObject(p));
}

function jsonPreview(obj, limit) {
  const value = objcToJs(obj, 4);
  if (value === null || value === undefined) return 'nil';
  return truncate(typeof value === 'string' ? value : JSON.stringify(value), limit || 4096);
}

function dataPreview(data) {
  if (data === null) return null;
  try {
    const length = Number(data.length());
    const bytes = readBytes(data.bytes(), Math.min(length, 512));
    return length + ' bytes: ' + fmt.bodyPreview(bytes, 512);
  } catch (_) {
    return null;
  }
}

function requestExtras(req, prefix, extras) {
  if (req === null) return null;
  let url = null;
  try { url = objcString(req.URL()); } catch (_) {}
  try {
    const method = req.HTTPMethod();
    if (method !== null) extras[prefix + 'method'] = { type: 'string', value: method.toString() };
  } catch (_) {}
  try {
    const headers = objcToJs(req.allHTTPHeaderFields(), 2);
    if (headers) {
      for (const key of Object.keys(headers)) {
        extras[prefix + 'headers/' + key] = { type: 'string', value: truncate(String(headers[key]), 1024) };
      }
    }
  } catch (_) {}
  try {
    const body = dataPreview(req.HTTPBody());
    if (body !== null) extras[prefix + 'body'] = { type: 'data', value: body };
  } catch (_) {}
  return url;
}

function isMainThread() {
  try {
    return Boolean(ObjC.classes.NSThread.isMainThread());
  } catch (_) {
    return false;
  }
}

// WKWebView properties may only be read on the main thread (WebKit asserts
// otherwise, which terminates the app).
function webViewUrl(webView) {
  if (webView === null || !isMainThread()) return null;
  try {
    return objcString(webView.URL());
  } catch (_) {
    return null;
  }
}

// Delegate-style web view hooks only patch classes shipped inside the app
// bundle (the app and its embedded frameworks/SDKs). Apple framework classes
// that implement the same delegate methods for their own web views are left
// alone.
let appBundlePath = null;

function isAppClass(className) {
  try {
    if (appBundlePath === null) appBundlePath = String(ObjC.classes.NSBundle.mainBundle().bundlePath());
    const klass = ObjC.classes[className];
    if (klass === undefined) return false;
    const image = ObjC.api.class_getImageName(klass.handle);
    return !image.isNull() && image.readUtf8String().indexOf(appBundlePath) === 0;
  } catch (_) {
    return false;
  }
}

function frameExtras(frame, prefix, extras) {
  if (frame === null) return null;
  let url = null;
  try { extras[prefix + 'mainFrame'] = { type: 'bool', value: frame.isMainFrame() ? 'true' : 'false' }; } catch (_) {}
  try { url = requestExtras(frame.request(), prefix + 'request/', extras); } catch (_) {}
  try {
    const origin = frame.securityOrigin();
    extras[prefix + 'origin'] = {
      type: 'string',
      value: objcString(origin.protocol()) + '://' + objcString(origin.host()) + (Number(origin.port()) ? ':' + Number(origin.port()) : ''),
    };
  } catch (_) {}
  return url;
}

// Interceptable web view event around a replaced method.
function webEvent(context, original, args, info, spec) {
  const ev = {
    className: runtimeClassName(args[0], info.className),
    methodName: (info.isClassMethod ? '+' : '-') + '[' + info.className + ' ' + info.selector + ']',
    component: spec.component || null,
    action: spec.action,
    data: spec.url || null,
    extras: spec.extras || {},
    interceptable: spec.interceptable !== false && !isNestedSelector(info.selector),
    mods: spec.mods || [],
    attackSurface: Object.assign({ platform: 'ios', direction: spec.direction }, spec.surface || {}),
    ipc: { kind: spec.kind || 'webview', direction: spec.direction, selector: info.selector, url: spec.url || null },
  };
  const r = withBusyThread(function () { return processEvent(ev, context); });
  if (r.mode === 'drop') {
    if (spec.onDrop) return spec.onDrop();
    return defaultReturn(info.returnType);
  }
  withBusyThread(function () {
    for (const mod of r.mods) {
      if (mod.type === 'data' && spec.setUrl) {
        const url = ObjC.classes.NSURL.URLWithString_(String(mod.val));
        if (url === null) {
          log('[!]', 'Invalid URL: ' + mod.val);
          continue;
        }
        keepTemp(url);
        spec.setUrl(url);
        log('[+]', 'URL replaced with ' + mod.val);
      } else if (mod.type === 'extra_add') {
        applyObjCArgMods(info.encodings, args, [mod]);
      }
    }
  });
  return callOriginal(original, args, info.selector);
}

function hookPattern(pattern, handler) {
  let count = 0;
  for (const target of resolveObjCPattern(pattern)) {
    if (!isAppClass(target.className)) continue;
    if (hookObjCTarget(target, handler)) count += 1;
  }
  return count;
}

function attachPattern(pattern, callbacks) {
  let count = 0;
  for (const target of resolveObjCPattern(pattern)) {
    if (!isAppClass(target.className)) continue;
    const klass = ObjC.classes[target.className];
    if (klass === undefined) continue;
    if (attachObjCMethod(klass, (target.isClassMethod ? '+ ' : '- ') + target.selector, callbacks)) count += 1;
  }
  return count;
}

function observeWeb(context, ev) {
  withBusyThread(function () {
    processEvent(Object.assign({
      className: 'WebKit',
      interceptable: false,
      mods: [],
      extras: {},
    }, ev, {
      attackSurface: Object.assign({ platform: 'ios', direction: ev.direction }, ev.surface || {}),
      ipc: Object.assign({ kind: ev.kind || 'webview', direction: ev.direction }, ev.ipc || {}),
    }), context);
  });
}

// JS -> native bridges: WKScriptMessageHandler messages, bridge registrations,
// injected user scripts and objects exposed through JavaScriptCore.
function hookWebBridges() {
  let count = 0;
  const onMessage = function (withReply) {
    return function (original, args, info) {
      const msg = wrapObject(args[3]);
      const extras = {};
      let name = null;
      let url = null;
      if (msg !== null) {
        try { name = objcString(msg.name()); } catch (_) {}
        try { extras.body = { type: 'json', value: jsonPreview(msg.body()) }; } catch (_) {}
        try { url = frameExtras(msg.frameInfo(), 'frame/', extras); } catch (_) {}
        try { extras['webView/url'] = { type: 'url', value: webViewUrl(msg.webView()) }; } catch (_) {}
      }
      if (name !== null) extras.name = { type: 'string', value: name };
      if (withReply) extras.replyHandler = { type: 'block', value: '<reply>' };
      return webEvent(this.context, original, args, info, {
        direction: 'incoming', action: 'script message', component: name, url: url, extras: extras,
        surface: { exposure: 'js_bridge' },
      });
    };
  };
  count += hookPattern('-[* userContentController:didReceiveScriptMessage:]', onMessage(false));
  count += hookPattern('-[* userContentController:didReceiveScriptMessage:replyHandler:]', onMessage(true));

  const W = ObjC.classes.WKUserContentController;
  if (W !== undefined) {
    const registration = function (nameIndex) {
      return {
        onEnter(args, info) {
          const handler = wrapObject(args[2]);
          const name = objString(args[nameIndex]);
          observeWeb(this.context, {
            methodName: '-[WKUserContentController ' + info.selector + ']',
            component: name, action: 'register JS bridge', direction: 'incoming',
            extras: {
              name: { type: 'string', value: name },
              handler: { type: 'class', value: handler !== null ? handler.$className : 'nil' },
              replies: { type: 'bool', value: info.selector.indexOf('WithReply') !== -1 ? 'true' : 'false' },
            },
            surface: { exposure: 'js_bridge' },
          });
        },
      };
    };
    if (attachObjCMethod(W, '- addScriptMessageHandler:name:', registration(3))) count += 1;
    if (attachObjCMethod(W, '- addScriptMessageHandler:contentWorld:name:', registration(4))) count += 1;
    if (attachObjCMethod(W, '- addScriptMessageHandlerWithReply:contentWorld:name:', registration(4))) count += 1;
    if (attachObjCMethod(W, '- addUserScript:', {
      onEnter(args) {
        const script = wrapObject(args[2]);
        let source = null;
        let mainFrameOnly = null;
        try { source = objcString(script.source()); } catch (_) {}
        try { mainFrameOnly = script.isForMainFrameOnly() ? 'true' : 'false'; } catch (_) {}
        observeWeb(this.context, {
          methodName: '-[WKUserContentController addUserScript:]',
          action: 'inject user script', direction: 'outgoing',
          extras: {
            source: { type: 'javascript', value: truncate(source, 4096) },
            mainFrameOnly: { type: 'bool', value: mainFrameOnly },
          },
        });
      },
    })) count += 1;
  }

  const J = ObjC.classes.JSContext;
  if (J !== undefined) {
    if (attachObjCMethod(J, '- setObject:forKeyedSubscript:', {
      onEnter(args) {
        const obj = wrapObject(args[2]);
        const key = objString(args[3]);
        observeWeb(this.context, {
          className: 'JavaScriptCore',
          methodName: '-[JSContext setObject:forKeyedSubscript:]',
          component: key, action: 'expose native object', direction: 'incoming',
          extras: {
            name: { type: 'string', value: key },
            object: { type: obj !== null ? obj.$className : 'nil', value: obj !== null ? truncate(objcString(obj), 512) : 'nil' },
          },
          surface: { exposure: 'js_bridge' },
          ipc: { engine: 'JavaScriptCore' },
        });
      },
    })) count += 1;
  }
  return count;
}

// Native -> web content: page loads and JavaScript evaluated by the app.
// WebKit's own methods get passive hooks (the implementation is never
// replaced). Modifications rewrite the arguments before the original runs;
// "drop" substitutes a harmless argument (about:blank, empty HTML,
// `void 0`) because a passive hook cannot skip the call.
function attachWebCall(klass, name, describe) {
  return attachObjCMethod(klass, name, {
    onEnter(args, info) {
      const spec = describe(args, info);
      const ev = {
        className: spec.className || info.className,
        methodName: '-[' + info.className + ' ' + info.selector + ']',
        component: spec.component || null,
        action: spec.action,
        data: spec.url || null,
        extras: spec.extras || {},
        interceptable: spec.interceptable !== false,
        mods: spec.mods || [],
        attackSurface: { platform: 'ios', direction: 'outgoing' },
        ipc: { kind: 'webview', direction: 'outgoing', selector: info.selector, url: spec.url || null },
      };
      const r = withBusyThread(function () { return processEvent(ev, this.context); }.bind(this));
      withBusyThread(function () {
        if (r.mode === 'drop') {
          if (spec.drop) {
            spec.drop(args);
            log('[+]', info.selector + ' neutralised (dropped)');
          } else {
            log('[~]', info.selector + ' cannot be dropped; forwarded unchanged');
          }
          return;
        }
        for (const mod of r.mods) {
          if (mod.type === 'data' && spec.setUrl) {
            const url = ObjC.classes.NSURL.URLWithString_(String(mod.val));
            if (url === null) {
              log('[!]', 'Invalid URL: ' + mod.val);
              continue;
            }
            keepTemp(url);
            spec.setUrl(args, url);
            log('[+]', 'URL replaced with ' + mod.val);
          } else if (mod.type === 'extra_add') {
            applyObjCArgMods(info.encodings, args, [mod]);
          }
        }
      });
    },
  });
}

function nsString(text) {
  const value = ObjC.classes.NSString.stringWithString_(text);
  keepTemp(value);
  return value.handle;
}

function blankRequest() {
  const request = ObjC.classes.NSURLRequest.requestWithURL_(ObjC.classes.NSURL.URLWithString_('about:blank'));
  keepTemp(request);
  return request.handle;
}

function hookWebLoads() {
  let count = 0;
  for (const viewClass of ['WKWebView', 'UIWebView']) {
    const V = ObjC.classes[viewClass];
    if (V === undefined) continue;
    const add = function (name, describe) {
      if (V[name] !== undefined && attachWebCall(V, name, describe)) count += 1;
    };
    add('- loadRequest:', function (args) {
      const extras = {};
      const url = requestExtras(wrapObject(args[2]), 'request/', extras);
      return {
        action: 'load request', component: fmt.hostOf(url), url: url, extras: extras, mods: ['data'],
        // Replaces the whole request: headers and body of the original are not kept.
        setUrl: function (a, newUrl) {
          const request = ObjC.classes.NSURLRequest.requestWithURL_(newUrl);
          keepTemp(request);
          a[2] = request.handle;
        },
        drop: function (a) { a[2] = blankRequest(); },
      };
    });
    add('- loadHTMLString:baseURL:', function (args) {
      const base = objString(args[3]);
      return {
        action: 'load HTML', component: fmt.hostOf(base), url: base, mods: ['data', 'extra_add'],
        extras: { arg0: { type: 'html', value: truncate(objString(args[2]), 4096) }, baseURL: { type: 'url', value: base } },
        setUrl: function (a, newUrl) { a[3] = newUrl.handle; },
        drop: function (a) { a[2] = nsString(''); a[3] = NULL; },
      };
    });
    add('- loadFileURL:allowingReadAccessToURL:', function (args) {
      return {
        action: 'load file', url: objString(args[2]), mods: ['data'],
        extras: { readAccessURL: { type: 'url', value: objString(args[3]) } },
        setUrl: function (a, newUrl) { a[2] = newUrl.handle; },
      };
    });
    add('- loadData:MIMEType:characterEncodingName:baseURL:', function (args) {
      const base = objString(args[5]);
      return {
        action: 'load data', component: fmt.hostOf(base), url: base, interceptable: false,
        extras: { data: { type: 'data', value: dataPreview(wrapObject(args[2])) }, mimeType: { type: 'string', value: objString(args[3]) } },
      };
    });
    const evaluate = function (args) {
      const page = webViewUrl(wrapObject(args[0]));
      return {
        action: 'evaluate JavaScript', component: fmt.hostOf(page), url: page, mods: ['extra_add'],
        extras: { arg0: { type: 'javascript', value: truncate(objString(args[2]), 4096) } },
        drop: function (a) { a[2] = nsString('void 0'); },
      };
    };
    add('- evaluateJavaScript:completionHandler:', evaluate);
    add('- evaluateJavaScript:inFrame:inContentWorld:completionHandler:', evaluate);
    add('- callAsyncJavaScript:arguments:inFrame:inContentWorld:completionHandler:', evaluate);
    add('- stringByEvaluatingJavaScriptFromString:', evaluate);
  }
  const J = ObjC.classes.JSContext;
  if (J !== undefined) {
    const evaluateScript = function (args) {
      return {
        className: 'JavaScriptCore', action: 'evaluate JavaScript', interceptable: false,
        extras: { arg0: { type: 'javascript', value: truncate(objString(args[2]), 4096) } },
      };
    };
    for (const name of ['- evaluateScript:', '- evaluateScript:withSourceURL:']) {
      if (J[name] !== undefined && attachWebCall(J, name, evaluateScript)) count += 1;
    }
  }
  return count;
}

// Navigation decisions made by the app's web view delegates. Dropping one
// cancels the navigation.
function hookWebNavigation() {
  let count = 0;
  const wk = function (withPreferences) {
    return function (original, args, info) {
      const action = wrapObject(args[3]);
      const handler = withPreferences ? args[5] : args[4];
      const extras = {};
      let url = null;
      if (action !== null) {
        try { url = requestExtras(action.request(), 'request/', extras); } catch (_) {}
        try { extras.navigationType = { type: 'string', value: fmt.navigationTypeName(action.navigationType()) }; } catch (_) {}
        try {
          const target = action.targetFrame();
          extras.targetFrame = { type: 'string', value: target === null ? 'new window' : (target.isMainFrame() ? 'main' : 'subframe') };
        } catch (_) {}
        try { frameExtras(action.sourceFrame(), 'sourceFrame/', extras); } catch (_) {}
      }
      return webEvent(this.context, original, args, info, {
        direction: 'incoming', action: 'navigation', component: fmt.hostOf(url), url: url, extras: extras,
        onDrop: function () {
          try {
            const block = new ObjC.Block(handler);
            if (withPreferences) block.implementation(0, args[4]);
            else block.implementation(0);
            log('[+]', 'Navigation cancelled (dropped)');
          } catch (e) {
            log('[!]', 'Could not cancel navigation: ' + e);
          }
        },
      });
    };
  };
  count += hookPattern('-[* webView:decidePolicyForNavigationAction:decisionHandler:]', wk(false));
  count += hookPattern('-[* webView:decidePolicyForNavigationAction:preferences:decisionHandler:]', wk(true));
  count += hookPattern('-[* webView:shouldStartLoadWithRequest:navigationType:]', function (original, args, info) {
    const extras = {};
    const url = requestExtras(wrapObject(args[3]), 'request/', extras);
    extras.navigationType = { type: 'string', value: fmt.navigationTypeName(Number(args[4])) };
    return webEvent(this.context, original, args, info, {
      direction: 'incoming', action: 'navigation', component: fmt.hostOf(url), url: url, extras: extras,
      onDrop: function () { return 0; },
    });
  });
  return count;
}

// Custom URL schemes served to web views, in-app browsers and OAuth sessions.
function hookWebSchemes() {
  let count = 0;
  const C = ObjC.classes.WKWebViewConfiguration;
  if (C !== undefined && attachObjCMethod(C, '- setURLSchemeHandler:forURLScheme:', {
    onEnter(args) {
      const handler = wrapObject(args[2]);
      const scheme = objString(args[3]);
      observeWeb(this.context, {
        methodName: '-[WKWebViewConfiguration setURLSchemeHandler:forURLScheme:]',
        component: scheme, action: 'register URL scheme handler', direction: 'incoming',
        extras: {
          scheme: { type: 'string', value: scheme },
          handler: { type: 'class', value: handler !== null ? handler.$className : 'nil' },
        },
        surface: { exposure: 'webview_scheme' },
      });
    },
  })) count += 1;
  count += attachPattern('-[* webView:startURLSchemeTask:]', {
    onEnter(args, info) {
      const task = wrapObject(args[3]);
      const extras = {};
      let url = null;
      try { url = requestExtras(task.request(), 'request/', extras); } catch (_) {}
      observeWeb(this.context, {
        className: info.className,
        methodName: '-[' + info.className + ' webView:startURLSchemeTask:]',
        component: url ? url.split(':')[0] : null, action: 'URL scheme request', direction: 'incoming',
        data: url, extras: extras, surface: { exposure: 'webview_scheme' },
      });
    },
  });
  const browsers = [
    ['SFSafariViewController', '- initWithURL:'],
    ['SFSafariViewController', '- initWithURL:configuration:'],
    ['SFSafariViewController', '- initWithURL:entersReaderIfAvailable:'],
    ['ASWebAuthenticationSession', '- initWithURL:callbackURLScheme:completionHandler:'],
    ['SFAuthenticationSession', '- initWithURL:callbackURLScheme:completionHandler:'],
  ];
  for (const [className, name] of browsers) {
    const K = ObjC.classes[className];
    if (K === undefined) continue;
    if (attachObjCMethod(K, name, {
      onEnter(args, info) {
        const url = objString(args[2]);
        const extras = {};
        if (info.selector.indexOf('callbackURLScheme') !== -1) {
          extras.callbackURLScheme = { type: 'string', value: objString(args[3]) };
        }
        observeWeb(this.context, {
          className: className,
          methodName: '-[' + className + ' ' + info.selector + ']',
          component: fmt.hostOf(url), action: className.indexOf('Authentication') !== -1 ? 'web authentication' : 'in-app browser',
          direction: 'outgoing', data: url, extras: extras,
        });
      },
    })) count += 1;
  }
  return count;
}

// --- Network requests (observe-only) ----------------------------------------------

const networkThreads = new Set();

function isNetworkTaskMethod(name) {
  return /^- (data|upload|download)TaskWith(Request|URL):/.test(name) ||
    /^- webSocketTaskWith(URL|Request):/.test(name) ||
    name === '- streamTaskWithHostName:port:';
}

function networkSessionClasses() {
  // NSURLSession is a class cluster: sessions are usually the private
  // __NSURLSessionLocal subclass, which overrides the task methods.
  const out = [];
  for (const name of ['NSURLSession', '__NSURLSessionLocal']) {
    const klass = ObjC.classes[name];
    if (klass === undefined) continue;
    try {
      const image = ObjC.api.class_getImageName(klass.handle).readUtf8String();
      if (image.indexOf('CFNetwork') === -1 && image.indexOf('Foundation') === -1) continue;
    } catch (_) {
      continue;
    }
    out.push(klass);
  }
  return out;
}

function hookNetworkRequests() {
  let count = 0;
  for (const S of networkSessionClasses()) {
    for (const name of S.$ownMethods.filter(isNetworkTaskMethod)) {
      if (attachNetworkMethod(S, name)) count += 1;
    }
  }
  return count;
}

function attachNetworkMethod(S, name) {
    return attachObjCMethod(S, name, {
      onEnter(args, info) {
        const tid = Process.getCurrentThreadId();
        // Convenience variants call the designated ones: report the outermost.
        if (networkThreads.has(tid)) return;
        networkThreads.add(tid);
        this.networkTid = tid;
        const extras = {};
        let url = null;
        let method = null;
        if (info.selector === 'streamTaskWithHostName:port:') {
          url = 'tcp://' + objString(args[2]) + ':' + args[3].toInt32();
        } else {
          const target = wrapObject(args[2]);
          if (target !== null && target.isKindOfClass_(ObjC.classes.NSURLRequest)) {
            url = requestExtras(target, '', extras);
            method = extras.method ? extras.method.value : null;
          } else {
            url = objcString(target);
          }
        }
        if (info.selector.indexOf('fromData:') !== -1) {
          const body = dataPreview(wrapObject(args[3]));
          if (body !== null) extras.body = { type: 'data', value: body };
        } else if (info.selector.indexOf('fromFile:') !== -1) {
          extras.file = { type: 'url', value: objString(args[3]) };
        }
        withBusyThread(function () {
          processEvent({
            className: 'CFNetwork',
            methodName: '-[' + info.className + ' ' + info.selector + ']',
            component: fmt.hostOf(url), action: method || info.selector.split('With')[0],
            data: url, extras: extras, interceptable: false, mods: [],
            attackSurface: { platform: 'ios', direction: 'outgoing' },
            ipc: { kind: 'network', direction: 'outgoing', url: url },
          }, this.context);
        }.bind(this));
      },
      onLeave() {
        if (this.networkTid !== undefined) networkThreads.delete(this.networkTid);
      },
    });
}

// --- Darwin notifications -----------------------------------------------------------

function hookNotify(entry) {
  const fn = entry.function;
  const addr = findExport(fn, 'libsystem_notify.dylib');
  if (addr === null) {
    if (!entry.optional) throw new Error(fn + ' not found');
    return false;
  }
  const intercept = entry.intercept !== false;
  if (fn === 'notify_post') {
    const orig = new NativeFunction(addr, 'uint32', ['pointer']);
    const cb = new NativeCallback(function (namePtr) {
      if (shouldPassthrough()) return orig(namePtr);
      const name = readCString(namePtr);
      const r = withBusyThread(function () {
        return processEvent({
          className: moduleNameFor(this.returnAddress) || 'unknown',
          methodName: fn,
          component: name,
          action: 'post',
          interceptable: intercept,
          mods: [],
          attackSurface: { platform: 'ios', direction: 'outgoing', exposure: 'darwin_notification' },
          ipc: { kind: 'darwin_notification', direction: 'outgoing', name: name },
        }, this.context);
      }.bind(this));
      return r.mode === 'drop' ? 0 : orig(namePtr);
    }, 'uint32', ['pointer']);
    Interceptor.replace(addr, cb);
    keepAlive.push(cb);
    return true;
  }
  // notify_register_*: observe registrations (any process may post Darwin
  // notifications, so every registration is attack surface).
  Interceptor.attach(addr, {
    onEnter(args) {
      if (shouldPassthrough()) return;
      const name = readCString(args[0]);
      const context = this.context;
      const caller = moduleNameFor(this.returnAddress) || 'unknown';
      withBusyThread(function () {
        processEvent({
          className: caller,
          methodName: fn,
          component: name,
          action: 'register',
          interceptable: false,
          attackSurface: { platform: 'ios', direction: 'incoming', exposure: 'darwin_listener' },
          ipc: { kind: 'darwin_notification', direction: 'incoming', name: name },
        }, context);
      });
    },
  });
  return true;
}

// --- Custom Objective-C hooks -----------------------------------------------------

function hookCustomObjC(entry) {
  const pattern = entry.method;
  const targets = /[*?]/.test(pattern) ? resolveObjCPattern(pattern) : (function () {
    const m = /^([+-])\[(\S+) (.+)\]$/.exec(pattern);
    if (m === null) throw new Error('invalid method spec ' + pattern + ' (expected "-[Class selector:]")');
    return [{ isClassMethod: m[1] === '+', className: m[2], selector: m[3] }];
  })();
  let count = 0;
  for (const target of targets) {
    const ok = hookObjCTarget(target, function (original, args, info) {
      return objcCallEvent(this.context, original, args, info, {
        interceptable: entry.intercept !== false && !isNestedSelector(info.selector),
        component: entry.component || info.className,
        attackSurface: { platform: 'ios', direction: entry.direction || 'incoming' },
        ipc: { kind: 'objc', direction: entry.direction || 'incoming', selector: info.selector, receiverClass: info.className },
      }).value;
    });
    if (ok) count += 1;
  }
  if (count === 0) {
    if (entry.optional) return 'none';
    throw new Error('no methods matched ' + pattern);
  }
  return count;
}

// --- Static attack surface ---------------------------------------------------------

function objcToJs(obj, depth) {
  if (obj === null || obj === undefined) return null;
  if (depth < 0) return objcString(obj);
  const C = ObjC.classes;
  try {
    if (obj.isKindOfClass_(C.NSString)) return obj.toString();
    if (obj.isKindOfClass_(C.NSNumber)) {
      const s = obj.toString();
      const n = Number(s);
      return isNaN(n) ? s : n;
    }
    if (obj.isKindOfClass_(C.NSArray)) {
      const out = [];
      const count = Math.min(obj.count(), 256);
      for (let i = 0; i < count; i++) out.push(objcToJs(obj.objectAtIndex_(i), depth - 1));
      return out;
    }
    if (obj.isKindOfClass_(C.NSDictionary)) {
      const out = {};
      const keys = obj.allKeys();
      const count = Math.min(keys.count(), 256);
      for (let i = 0; i < count; i++) {
        const key = keys.objectAtIndex_(i);
        out[key.toString()] = objcToJs(obj.objectForKey_(key), depth - 1);
      }
      return out;
    }
    if (obj.isKindOfClass_(C.NSData)) return '<' + obj.length() + ' bytes>';
  } catch (_) {}
  return objcString(obj);
}

function readMainEntitlements() {
  const main = Process.mainModule || Process.enumerateModules()[0];
  const base = main.base;
  if (base.readU32() !== 0xfeedfacf) return null;
  const ncmds = base.add(16).readU32();
  let lc = base.add(32);
  let textVm = null;
  let linkedit = null;
  let signature = null;
  for (let i = 0; i < ncmds; i++) {
    const cmd = lc.readU32();
    const size = lc.add(4).readU32();
    if (cmd === 0x19) {
      const segname = lc.add(8).readCString(16);
      if (segname === '__TEXT') textVm = lc.add(24).readU64();
      if (segname === '__LINKEDIT') linkedit = { vm: lc.add(24).readU64(), fileoff: lc.add(40).readU64() };
    } else if (cmd === 0x1d) {
      signature = { dataoff: lc.add(8).readU32(), datasize: lc.add(12).readU32() };
    }
    lc = lc.add(size);
  }
  if (textVm === null || linkedit === null || signature === null) return null;
  const slide = base.sub(ptr(textVm.toString()));
  const address = slide.add(ptr(linkedit.vm.toString())).add(signature.dataoff - linkedit.fileoff.toNumber());
  return fmt.entitlementsFromSuperBlob(readBytes(address, signature.datasize));
}

function listExtensions(bundle) {
  const out = [];
  try {
    const dir = bundle.builtInPlugInsPath();
    if (dir === null) return out;
    const fm = ObjC.classes.NSFileManager.defaultManager();
    const items = fm.contentsOfDirectoryAtPath_error_(dir, NULL);
    if (items === null) return out;
    for (let i = 0; i < items.count(); i++) {
      const name = items.objectAtIndex_(i).toString();
      if (!name.endsWith('.appex')) continue;
      const path = dir.toString() + '/' + name;
      const ext = ObjC.classes.NSBundle.bundleWithPath_(path);
      const info = ext !== null ? objcToJs(ext.infoDictionary(), 4) || {} : {};
      const nsext = info.NSExtension || {};
      out.push({
        name: name,
        bundleId: info.CFBundleIdentifier || null,
        point: nsext.NSExtensionPointIdentifier || null,
        principalClass: nsext.NSExtensionPrincipalClass || null,
        attributes: nsext.NSExtensionAttributes || null,
      });
    }
  } catch (e) {
    log('[~]', 'Extension enumeration failed: ' + e);
  }
  return out;
}

function staticAttackSurface() {
  const out = { platform: 'ios', pid: Process.id, process: null, bundle: null, entitlements: null };
  try {
    const main = Process.mainModule || Process.enumerateModules()[0];
    out.process = { name: main.name, path: main.path };
  } catch (_) {}
  try {
    out.entitlements = readMainEntitlements();
  } catch (e) {
    log('[~]', 'Entitlements unavailable: ' + e);
  }
  if (!objcAvailable() || ObjC.classes.NSBundle === undefined) return out;
  try {
    const bundle = ObjC.classes.NSBundle.mainBundle();
    const info = objcToJs(bundle.infoDictionary(), 5) || {};
    out.bundle = {
      identifier: info.CFBundleIdentifier || null,
      name: info.CFBundleDisplayName || info.CFBundleName || null,
      version: info.CFBundleShortVersionString || null,
      build: info.CFBundleVersion || null,
      executable: info.CFBundleExecutable || null,
      path: objcString(bundle.bundlePath()),
      minimumOS: info.MinimumOSVersion || null,
    };
    out.urlTypes = (info.CFBundleURLTypes || []).map(t => ({
      name: t.CFBundleURLName || null,
      schemes: t.CFBundleURLSchemes || [],
      role: t.CFBundleTypeRole || null,
    }));
    out.queriedSchemes = info.LSApplicationQueriesSchemes || [];
    out.userActivityTypes = info.NSUserActivityTypes || [];
    out.documentTypes = (info.CFBundleDocumentTypes || []).map(t => ({
      name: t.CFBundleTypeName || null,
      types: t.LSItemContentTypes || [],
      role: t.CFBundleTypeRole || null,
    }));
    out.exportedTypes = (info.UTExportedTypeDeclarations || []).map(t => t.UTTypeIdentifier || null);
    out.backgroundModes = info.UIBackgroundModes || [];
    out.supportsDocumentBrowser = Boolean(info.UISupportsDocumentBrowser);
    out.fileSharing = Boolean(info.UIFileSharingEnabled);
    out.openInPlace = Boolean(info.LSSupportsOpeningDocumentsInPlace);
    out.extensions = listExtensions(bundle);
  } catch (e) {
    log('[!]', 'Static attack surface failed: ' + e);
  }
  return out;
}

// --- Entry point --------------------------------------------------------------------

function installHook(entry) {
  const kind = entry.kind;
  if (kind === 'xpc') {
    if (X.xpc_get_type === null) throw new Error('libxpc not loaded');
    return hookXpc(entry);
  }
  if (kind === 'notify') return hookNotify(entry);
  if (kind === 'nsxpc' || kind === 'url' || kind === 'objc' || kind === 'webview' || kind === 'network') {
    if (!objcAvailable()) {
      log('[~]', 'Skipping ' + describeEntry(entry) + ' (Objective-C runtime not available)');
      return false;
    }
    if (kind === 'objc') return hookCustomObjC(entry);
    if (kind === 'nsxpc' && entry.feature === 'connections') return hookNSXPCConnections();
    if (kind === 'nsxpc' && entry.feature === 'listeners') return hookNSXPCListeners();
    if (kind === 'nsxpc' && entry.feature === 'replies') {
      // Swaps reply blocks inside outgoing invocations; opt-in because it
      // changes the objects Foundation sees.
      decodeReplies = true;
      return true;
    }
    if (kind === 'url' && entry.feature === 'incoming') return hookUrlIncoming() > 0 || 'none';
    if (kind === 'url' && entry.feature === 'outgoing') return hookUrlOutgoing() > 0 || 'none';
    if (kind === 'webview' && entry.feature === 'bridges') return hookWebBridges() > 0 || 'none';
    if (kind === 'webview' && entry.feature === 'loads') return hookWebLoads() > 0 || 'none';
    if (kind === 'webview' && entry.feature === 'navigation') return hookWebNavigation() > 0 || 'none';
    if (kind === 'webview' && entry.feature === 'schemes') return hookWebSchemes() > 0 || 'none';
    if (kind === 'network' && entry.feature === 'requests') return hookNetworkRequests() > 0 || 'none';
  }
  throw new Error('unknown hook definition');
}

function describeEntry(entry) {
  return entry.kind + ':' + (entry.function || entry.feature || entry.method || '?');
}

function rpcGuard(fn) {
  return function () {
    rpcDepth += 1;
    try {
      return fn.apply(null, arguments);
    } finally {
      rpcDepth -= 1;
    }
  };
}

// Native exception reporting. The report arrives even when the process then
// freezes instead of exiting (which can happen with Frida injected), so the
// user learns why the app stopped. An exception is not always a crash: some
// code (anti-debugging, crash reporters, JavaScript engines) raises and
// handles its own, so the host only reports and never kills on this basis.
// Only the first few are reported to keep handled, repeating ones cheap.
const MAX_EXCEPTION_REPORTS = 3;
let exceptionReports = 0;

function installCrashReporter() {
  Process.setExceptionHandler(function (details) {
    if (exceptionReports >= MAX_EXCEPTION_REPORTS) return false;
    exceptionReports += 1;
    try {
      const memory = details.memory || null;
      send({
        ioxenEvent: 'crash',
        sequence: exceptionReports,
        pid: Process.id,
        type: details.type,
        address: details.address ? frameLabel(details.address) : null,
        memory: memory ? { operation: memory.operation, address: memory.address.toString() } : null,
        threadId: Process.getCurrentThreadId(),
        stackTrace: captureStack(details.context),
      });
    } catch (_) {}
    return false; // let the app's own handlers, or the system, deal with it
  });
}

let initialized = false;
let lastReportedEvents = 0;

rpc.exports = {
  proxy: rpcGuard(function (hookConfig) {
    if (initialized) return;
    initialized = true;
    send('[*] Initializing iOS IPC hooks');
    const started = Date.now();
    try {
      installCrashReporter();
    } catch (e) {
      log('[~]', 'Crash reporting unavailable: ' + e);
    }
    initNative();
    if (xpcReady) {
      initApplyBlock();
      initWrapperInvoke();
      hookXpcCreation();
    } else {
      log('[~]', 'XPC block support unavailable; XPC message decoding is limited');
    }

    for (const entry of fmt.mergeHookEntries(hookConfig)) {
      try {
        const result = installHook(entry);
        if (result === true || typeof result === 'number') {
          report.hooks += 1;
          send('[~] Hooked ' + describeEntry(entry));
        } else if (result === 'none') {
          send('[~] No implementations found for ' + describeEntry(entry));
        }
      } catch (e) {
        report.failed += 1;
        log('[!]', 'Error registering hook ' + describeEntry(entry) + ': ' + e);
      }
    }
    send('[+] iOS IPC hooks initialized (' + report.hooks + ' active, ' + report.failed + ' failed, ' +
      (Date.now() - started) + ' ms)');
    // Verbose-log heartbeat: a launch that dies right after a burst of events
    // points at hook overhead (watchdog) rather than a hook crash.
    setInterval(function () {
      const seen = decisions.eventCount();
      if (seen !== lastReportedEvents) {
        send('[agent] ' + (seen - lastReportedEvents) + ' IPC events in the last 5 s (' + seen + ' total)');
        lastReportedEvents = seen;
      }
    }, 5000);
  }),

  forward: function (decisionId) {
    return decisions.forward(decisionId);
  },

  drop: function (decisionId) {
    return decisions.drop(decisionId);
  },

  stageMod: function (type, key, val, extraType, decisionId) {
    return decisions.stageMod(type, key, val, extraType, decisionId);
  },

  // Returns the id of the decision that was released (or null) so the host
  // can post its wake message.
  interceptoff: function () {
    return decisions.interceptOff();
  },

  intercepton: function () {
    decisions.interceptOn();
  },

  setFilters: function (ignoreList, focusList) {
    return decisions.setFilters(ignoreList, focusList);
  },

  getProcessInfo: rpcGuard(function () {
    const info = { platform: 'ios', pid: Process.id, arch: Process.arch, objc: objcAvailable(), xpc: xpcReady };
    try {
      const main = Process.mainModule || Process.enumerateModules()[0];
      info.process = main.name;
    } catch (_) {}
    return info;
  }),

  getAttackSurface: rpcGuard(function () {
    return staticAttackSurface();
  }),
};
