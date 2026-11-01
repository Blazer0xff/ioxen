// Integration harness for tests/test_ios_decision_protocol.py.
//
// Exercises the iOS agent's host decision protocol (agent/ios/decisions.js)
// with real Frida semantics on any platform: getuid() stands in for an XPC
// send so a test process can be held, forwarded, dropped and modified.
import { createDecisionCore } from '../../agent/ios/decisions.js';

const core = createDecisionCore({ jsThreadId: Process.getCurrentThreadId() });
const keep = [];
let installed = false;

rpc.exports = {
  proxy() {
    if (installed) return;
    installed = true;
    const addr = Module.getGlobalExportByName('getuid');
    const orig = new NativeFunction(addr, 'uint32', []);
    const cb = new NativeCallback(function () {
      const r = core.process({
        className: 'harness',
        methodName: 'getuid',
        component: 'com.example.harness',
        action: 'ping:',
        interceptable: true,
        mods: ['extra_add'],
        extras: { uid: { type: 'int64', value: 'real' } },
        attackSurface: { platform: 'ios', direction: 'outgoing' },
        ipc: { kind: 'xpc', direction: 'outgoing', peer: { pid: 1, path: '/sbin/launchd' } },
      }, this.context);
      if (r.mode === 'drop') return 4242;
      for (const m of r.mods) {
        if (m.key === 'uid') return parseInt(m.val, 10);
      }
      return orig();
    }, 'uint32', []);
    Interceptor.replace(addr, cb);
    keep.push(cb);
  },
  forward: (id) => core.forward(id),
  drop: (id) => core.drop(id),
  stageMod: (type, key, val, extraType, id) => core.stageMod(type, key, val, extraType, id),
  interceptoff: () => core.interceptOff(),
  intercepton: () => core.interceptOn(),
  setFilters: (ignore, focus) => core.setFilters(ignore, focus),
  getProcessInfo: () => ({ platform: 'ios', xpc: true, objc: true }),
};
