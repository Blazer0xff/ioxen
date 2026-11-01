// Pure helpers for the iOS agent. Nothing in this file may touch Frida
// globals (Process, Memory, ObjC, ...) so it can be unit-tested with plain
// Node.js (see tests/js/).

export const PATH_SEPARATOR = '/';

export const XPC_VALUE_TYPES = ['string', 'int64', 'uint64', 'bool', 'double', 'data'];

const XPC_TYPE_ALIASES = {
  string: 'string',
  int: 'int64',
  long: 'int64',
  int64: 'int64',
  uint64: 'uint64',
  bool: 'bool',
  boolean: 'bool',
  float: 'double',
  double: 'double',
  data: 'data',
};

export function normalizeValueType(type) {
  return XPC_TYPE_ALIASES[String(type || 'string').toLowerCase()] || null;
}

// --- Filters (mirror of ioxen.filters.FilterManager.check_match) ----------

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\\/]/g, '\\$&');
}

// Port of Python's fnmatch.translate(): '*', '?', '[seq]' and '[!seq]'.
export function globToRegExp(pattern) {
  let out = '';
  let i = 0;
  const n = pattern.length;
  while (i < n) {
    const c = pattern[i];
    i += 1;
    if (c === '*') {
      out += '[\\s\\S]*';
    } else if (c === '?') {
      out += '[\\s\\S]';
    } else if (c === '[') {
      let j = i;
      if (j < n && pattern[j] === '!') j += 1;
      if (j < n && pattern[j] === ']') j += 1;
      while (j < n && pattern[j] !== ']') j += 1;
      if (j >= n) {
        out += '\\[';
      } else {
        let stuff = pattern.slice(i, j).replace(/\\/g, '\\\\');
        i = j + 1;
        if (stuff[0] === '!') stuff = '^' + stuff.slice(1);
        else if (stuff[0] === '^') stuff = '\\' + stuff;
        out += '[' + stuff + ']';
      }
    } else {
      out += escapeRegExp(c);
    }
  }
  return new RegExp('^(?:' + out + ')$');
}

const globCache = new Map();

export function fnmatch(value, pattern) {
  let re = globCache.get(pattern);
  if (re === undefined) {
    re = globToRegExp(pattern);
    if (globCache.size > 512) globCache.clear();
    globCache.set(pattern, re);
  }
  return re.test(value);
}

export function checkMatch(context, rules) {
  for (const rule of rules) {
    let matches = true;
    for (const key of Object.keys(rule)) {
      const p = rule[key];
      if (!(key in context)) {
        matches = false;
        break;
      }
      const val = context[key];
      if (p === 'set' || p === 'unset') {
        const isSet = Array.isArray(val) ? val.length > 0 : Boolean(val);
        const wantSet = p === 'set';
        if (isSet !== wantSet) {
          matches = false;
          break;
        }
      } else if (Array.isArray(val)) {
        if (!val.some(v => fnmatch(v, p))) {
          matches = false;
          break;
        }
      } else if (!fnmatch(val, p)) {
        matches = false;
        break;
      }
    }
    if (matches) return true;
  }
  return false;
}

export function isVisible(context, ignoreList, focusList) {
  if (focusList && focusList.length) return checkMatch(context, focusList);
  return !checkMatch(context, ignoreList || []);
}

// Mirror of ioxen.rendering.payload_to_filter_context().
export function buildFilterContext(payload) {
  const info = payload.infoIntent || {};
  const ipc = payload.ipc || {};
  const peer = ipc.peer || {};
  return {
    class: String(payload.className || ''),
    method: String(payload.methodName || ''),
    action: String(info.action || ''),
    component: String(info.component || ''),
    data: String(info.data || ''),
    direction: String(ipc.direction || ''),
    peer: peerLabel(peer),
  };
}

export function peerLabel(peer) {
  if (!peer) return '';
  if (peer.path) return String(peer.path);
  if (peer.pid !== undefined && peer.pid !== null && peer.pid > 0) return String(peer.pid);
  return '';
}

// --- Byte helpers -----------------------------------------------------------

const HEX = '0123456789abcdef';

export function toHex(bytes, limit) {
  const n = Math.min(bytes.length, limit === undefined ? bytes.length : limit);
  let out = '';
  for (let i = 0; i < n; i++) {
    out += HEX[bytes[i] >> 4] + HEX[bytes[i] & 0x0f];
  }
  return out;
}

export function parseHex(text) {
  const clean = String(text || '').replace(/^0x/i, '').replace(/[\s:]/g, '');
  if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) return null;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.substr(i * 2, 2), 16);
  }
  return out;
}

const B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function toBase64(bytes) {
  let out = '';
  let i = 0;
  for (; i + 2 < bytes.length; i += 3) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out += B64[(v >> 18) & 63] + B64[(v >> 12) & 63] + B64[(v >> 6) & 63] + B64[v & 63];
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const v = bytes[i] << 16;
    out += B64[(v >> 18) & 63] + B64[(v >> 12) & 63] + '==';
  } else if (rest === 2) {
    const v = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out += B64[(v >> 18) & 63] + B64[(v >> 12) & 63] + B64[(v >> 6) & 63] + '=';
  }
  return out;
}

export function asciiPrefix(bytes, length) {
  let out = '';
  for (let i = 0; i < Math.min(length, bytes.length); i++) {
    out += String.fromCharCode(bytes[i]);
  }
  return out;
}

// Returns the binary plist flavour ("bplist00", "bplist16", ...) or null.
// bplist00 is a regular binary plist (often an NSKeyedArchiver archive);
// bplist15/16/17 are the private NSXPC serialization formats.
export function detectBplist(bytes) {
  if (bytes.length < 8) return null;
  const magic = asciiPrefix(bytes, 8);
  return /^bplist\d\d$/.test(magic) ? magic : null;
}

// Heuristic extraction of printable ASCII runs. NSXPC encodes selectors,
// class names and string arguments as plain ASCII inside bplist16 blobs, so
// this is a cheap way to surface them without a full bplist16 decoder.
export function extractStrings(bytes, minLength, maxStrings) {
  const min = minLength || 4;
  const max = maxStrings || 64;
  const out = [];
  const seen = new Set();
  let current = '';
  const flush = () => {
    if (current.length >= min && !seen.has(current) && !/^bplist\d\d$/.test(current)) {
      seen.add(current);
      out.push(current);
    }
    current = '';
  };
  for (let i = 0; i < bytes.length && out.length < max; i++) {
    const b = bytes[i];
    if (b >= 0x20 && b < 0x7f) {
      current += String.fromCharCode(b);
    } else {
      flush();
    }
  }
  if (out.length < max) flush();
  return out;
}

const SELECTOR_RE = /^[A-Za-z_][A-Za-z0-9_]*(?::(?:[A-Za-z_][A-Za-z0-9_]*:)*)?$/;

export function guessSelector(strings) {
  for (const s of strings || []) {
    if (s.indexOf(':') !== -1 && SELECTOR_RE.test(s)) return s;
  }
  return null;
}

// --- XPC object trees ------------------------------------------------------
//
// The agent decodes xpc_object_t values into small JSON trees:
//   {t: 'dictionary', v: [[key, node], ...]}
//   {t: 'array', v: [node, ...]}
//   {t: 'string'|'int64'|'uint64'|'bool'|'double'|'date'|'uuid', v: '...'}
//   {t: 'data', len: N, hex: '...', bplist: 'bplist16'|null, strings: [...]}
//   {t: 'fd'|'shmem'|'endpoint'|'connection'|'null'|'error'|..., v: '...'}
//   {t: 'truncated'}

export function describeNode(node) {
  if (!node) return '';
  switch (node.t) {
    case 'dictionary':
      return '{' + node.v.length + ' keys}';
    case 'array':
      return '[' + node.v.length + ' items]';
    case 'data': {
      let text = node.len + ' bytes';
      if (node.bplist) text += ' ' + node.bplist;
      if (node.hex) text += ' ' + node.hex + (node.len * 2 > node.hex.length ? '…' : '');
      return text;
    }
    case 'truncated':
      return '…';
    default:
      return node.v === undefined || node.v === null ? '' : String(node.v);
  }
}

export function joinPath(prefix, key) {
  return prefix ? prefix + PATH_SEPARATOR + key : key;
}

// Flattens a decoded XPC tree into ioxen "extras":
//   {"path/to/key": {type: "string", value: "..."}}
// Empty containers are kept so they stay visible; non-empty ones only
// contribute their children.
export function flattenTree(node, maxEntries) {
  const limit = maxEntries || 256;
  const out = {};
  let count = 0;
  let truncated = false;

  function visit(prefix, n) {
    if (count >= limit) {
      truncated = true;
      return;
    }
    if (n.t === 'dictionary' && n.v.length > 0) {
      for (const [key, child] of n.v) visit(joinPath(prefix, key), child);
      return;
    }
    if (n.t === 'array' && n.v.length > 0) {
      n.v.forEach((child, idx) => visit(prefix + '[' + idx + ']', child));
      return;
    }
    out[prefix || '(root)'] = { type: n.t, value: describeNode(n) };
    count += 1;
  }

  if (node) visit('', node);
  if (truncated) out['…'] = { type: 'truncated', value: 'more entries omitted' };
  return out;
}

export function collectBlobs(node, maxBlobs) {
  const limit = maxBlobs || 16;
  const out = [];
  function visit(prefix, n) {
    if (!n || out.length >= limit) return;
    if (n.t === 'dictionary') {
      for (const [key, child] of n.v) visit(joinPath(prefix, key), child);
    } else if (n.t === 'array') {
      n.v.forEach((child, idx) => visit(prefix + '[' + idx + ']', child));
    } else if (n.t === 'data' && (n.bplist || (n.strings && n.strings.length))) {
      const blob = { path: prefix || '(root)', length: n.len, format: n.bplist || null, strings: n.strings || [] };
      if (n.b64) blob.base64 = n.b64;
      out.push(blob);
    }
  }
  visit('', node);
  return out;
}

export function dictionaryKeys(node) {
  return node && node.t === 'dictionary' ? node.v.map(([key]) => key) : [];
}

export function findChild(node, key) {
  if (!node || node.t !== 'dictionary') return null;
  for (const [k, child] of node.v) {
    if (k === key) return child;
  }
  return null;
}

// NSXPC messages are XPC dictionaries carrying the invocation in a
// bplist16-encoded "root" data value.
export function nsxpcInfo(node) {
  const root = findChild(node, 'root');
  if (!root || root.t !== 'data' || !root.bplist || !/^bplist1[5-7]$/.test(root.bplist)) return null;
  return {
    encoding: root.bplist,
    selector: guessSelector(root.strings),
    strings: root.strings || [],
  };
}

export function splitPath(path) {
  return String(path).split(PATH_SEPARATOR).filter(part => part.length > 0);
}

// --- Objective-C type encodings ---------------------------------------------

const TYPE_QUALIFIERS = 'rnNoORVA';

function skipDigits(types, i) {
  while (i < types.length && types[i] >= '0' && types[i] <= '9') i += 1;
  return i;
}

function readBalanced(types, i, open, close) {
  let depth = 0;
  const start = i;
  for (; i < types.length; i++) {
    if (types[i] === open) depth += 1;
    else if (types[i] === close) {
      depth -= 1;
      if (depth === 0) return [types.slice(start, i + 1), i + 1];
    }
  }
  return [types.slice(start), types.length];
}

function readOneType(types, i) {
  while (i < types.length && TYPE_QUALIFIERS.indexOf(types[i]) !== -1) i += 1;
  const c = types[i];
  if (c === undefined) return [null, i];
  if (c === '@') {
    if (types[i + 1] === '?') {
      let end = i + 2;
      if (types[end] === '<') end = readBalanced(types, end, '<', '>')[1];
      return ['@?', end];
    }
    if (types[i + 1] === '"') {
      const close = types.indexOf('"', i + 2);
      if (close !== -1) return ['@"' + types.slice(i + 2, close) + '"', close + 1];
    }
    return ['@', i + 1];
  }
  if (c === '^') {
    const [inner, end] = readOneType(types, i + 1);
    return ['^' + (inner || ''), end];
  }
  if (c === '{') return readBalanced(types, i, '{', '}');
  if (c === '(') return readBalanced(types, i, '(', ')');
  if (c === '[') return readBalanced(types, i, '[', ']');
  if (c === 'b') return [types.slice(i, skipDigits(types, i + 1)), skipDigits(types, i + 1)];
  return [c, i + 1];
}

// "v40@0:8@16@?24q32" -> ['v', '@', ':', '@', '@?', 'q']
export function parseObjCTypes(types) {
  const out = [];
  let i = 0;
  const text = String(types || '');
  while (i < text.length) {
    const [type, next] = readOneType(text, i);
    if (type === null || next <= i) break;
    out.push(type);
    i = skipDigits(text, next);
  }
  return out;
}

export function objcTypeKind(encoding) {
  if (!encoding) return 'unknown';
  if (encoding === '@?') return 'block';
  if (encoding[0] === '@') return 'object';
  if (encoding === ':') return 'selector';
  if (encoding === '#') return 'class';
  if (encoding === '*') return 'cstring';
  if (encoding === 'B') return 'bool';
  if ('cislqCISLQ'.indexOf(encoding) !== -1) return 'integer';
  if (encoding === 'f' || encoding === 'd') return 'float';
  if (encoding === 'v') return 'void';
  if (encoding[0] === '^') return 'pointer';
  if (encoding[0] === '{') return 'struct';
  return 'unknown';
}

export function objcClassHint(encoding) {
  const m = /^@"([^"<]*)/.exec(encoding || '');
  return m && m[1] ? m[1] : null;
}

// --- Code signature / entitlements ------------------------------------------

const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171;
const CSSLOT_ENTITLEMENTS = 5;

function readU32BE(bytes, offset) {
  return ((bytes[offset] << 24) >>> 0) + (bytes[offset + 1] << 16) + (bytes[offset + 2] << 8) + bytes[offset + 3];
}

function decodeUtf8(bytes) {
  let out = '';
  let i = 0;
  while (i < bytes.length) {
    const b = bytes[i];
    let cp;
    if (b < 0x80) { cp = b; i += 1; }
    else if (b >= 0xc0 && b < 0xe0) { cp = ((b & 0x1f) << 6) | (bytes[i + 1] & 0x3f); i += 2; }
    else if (b >= 0xe0 && b < 0xf0) { cp = ((b & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f); i += 3; }
    else { cp = ((b & 0x07) << 18) | ((bytes[i + 1] & 0x3f) << 12) | ((bytes[i + 2] & 0x3f) << 6) | (bytes[i + 3] & 0x3f); i += 4; }
    out += String.fromCodePoint(cp);
  }
  return out;
}

// Extracts the XML entitlements plist from an embedded code signature
// (LC_CODE_SIGNATURE SuperBlob). Returns null when not present.
export function entitlementsFromSuperBlob(bytes) {
  if (!bytes || bytes.length < 12 || readU32BE(bytes, 0) !== CSMAGIC_EMBEDDED_SIGNATURE) return null;
  const count = readU32BE(bytes, 8);
  for (let idx = 0; idx < count; idx++) {
    const entry = 12 + idx * 8;
    if (entry + 8 > bytes.length) break;
    const type = readU32BE(bytes, entry);
    const offset = readU32BE(bytes, entry + 4);
    if (type !== CSSLOT_ENTITLEMENTS || offset + 8 > bytes.length) continue;
    if (readU32BE(bytes, offset) !== CSMAGIC_EMBEDDED_ENTITLEMENTS) continue;
    const length = readU32BE(bytes, offset + 4);
    const end = Math.min(bytes.length, offset + length);
    return decodeUtf8(bytes.subarray(offset + 8, end));
  }
  return null;
}

// --- NSXPC send layout ---------------------------------------------------------
//
// NSXPCConnection funnels remote calls through private methods whose shape
// changed across releases:
//   _sendInvocation:withProxy:                                     (invocation)
//   _sendInvocation:orArguments:count:methodSignature:selector:withProxy:
//                                       (invocation, or an id* argument array)
//   _sendSelector:withProxy:[arg1:[arg2:...]]          (fast path, id args)
// Given the private selector, returns the argument index (counting self and
// _cmd as 0 and 1) of each component, or null when the shape is unknown.
export function nsxpcSendLayout(privateSelector) {
  const parts = String(privateSelector || '').split(':').slice(0, -1);
  if (parts.length === 0) return null;
  const at = name => {
    const i = parts.indexOf(name);
    return i === -1 ? -1 : i + 2;
  };
  if (parts[0] === '_sendInvocation') {
    return {
      kind: 'invocation',
      invocation: 2,
      arguments: at('orArguments'),
      count: at('count'),
      signature: at('methodSignature'),
      selector: at('selector'),
      proxy: at('withProxy'),
      values: [],
    };
  }
  if (parts[0] === '_sendSelector') {
    const values = [];
    for (let i = 1; at('arg' + i) !== -1; i++) values.push(at('arg' + i));
    return { kind: 'selector', invocation: -1, arguments: -1, count: -1, signature: -1, selector: 2, proxy: at('withProxy'), values: values };
  }
  return null;
}

// Byte size and reader name for scalar ObjC type encodings stored in an
// NSInvocation argument buffer.
const SCALAR_LAYOUT = {
  c: [1, 'S8'], C: [1, 'U8'], B: [1, 'U8'], s: [2, 'S16'], S: [2, 'U16'],
  i: [4, 'S32'], I: [4, 'U32'], l: [8, 'S64'], L: [8, 'U64'], q: [8, 'S64'], Q: [8, 'U64'],
  f: [4, 'Float'], d: [8, 'Double'],
};

export function scalarLayout(encoding) {
  const stripped = String(encoding || '').replace(/^[rnNoORVA]+/, '');
  return SCALAR_LAYOUT[stripped] || null;
}

// Checks a send layout against the method's runtime type encodings
// ([ret, self, _cmd, arg2...], see parseObjCTypes) so private methods whose
// shape differs from what the agent expects are left alone.
export function validateSendLayout(layout, encodings) {
  if (!layout || !encodings || encodings.length < 3) return false;
  const kindAt = index => objcTypeKind(encodings[index + 1]);
  if (layout.proxy >= 0 && kindAt(layout.proxy) !== 'object') return false;
  if (layout.selector >= 0 && kindAt(layout.selector) !== 'selector') return false;
  if (layout.kind === 'invocation') return kindAt(layout.invocation) === 'object';
  if (layout.kind === 'selector') {
    return layout.selector >= 0 && layout.values.every(index => kindAt(index) === 'object');
  }
  return false;
}

// --- Hook configuration ----------------------------------------------------------

export function hookEntryKey(entry) {
  return [entry.kind, entry.function || entry.feature || entry.method || ''].join(':');
}

// Default and custom hook files are concatenated; a later entry with the same
// identity (kind + function/feature/method) replaces an earlier one, so a
// custom file can switch a built-in hook off with "enabled": false.
export function mergeHookEntries(entries) {
  const merged = new Map();
  for (const entry of entries || []) {
    if (!entry || typeof entry !== 'object' || entry.clazz !== undefined || !entry.kind) continue;
    const key = hookEntryKey(entry);
    merged.delete(key);
    merged.set(key, entry);
  }
  return Array.from(merged.values()).filter(entry => entry.enabled !== false);
}

// --- Web views / network -------------------------------------------------------------

const NAVIGATION_TYPES = {
  '-1': 'other', 0: 'link', 1: 'form submit', 2: 'back/forward', 3: 'reload', 4: 'form resubmit',
};

// WKNavigationType / UIWebViewNavigationType (same values for the shared cases).
export function navigationTypeName(value) {
  const name = NAVIGATION_TYPES[String(Number(value))];
  return name || String(value);
}

// Short human-readable preview of a request/response body: text when it is
// mostly printable, hex otherwise.
export function bodyPreview(bytes, limit) {
  const max = limit || 512;
  if (!bytes || bytes.length === 0) return '';
  const slice = bytes.subarray(0, max);
  let printable = 0;
  for (const b of slice) {
    if ((b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x0d || b === 0x09) printable += 1;
  }
  const more = bytes.length > max ? '…' : '';
  if (printable / slice.length >= 0.9) {
    let text = '';
    for (const b of slice) text += String.fromCharCode(b);
    return text + more;
  }
  return 'hex:' + toHex(slice) + more;
}

export function hostOf(url) {
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\/(?:[^@/?#]*@)?([^:/?#]+)/.exec(String(url || ''));
  return m ? m[1].toLowerCase() : null;
}
