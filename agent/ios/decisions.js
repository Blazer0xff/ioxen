// Host decision protocol shared by the iOS agent.
//
// An interceptable event is sent to the host together with a decision id;
// the hooked thread then parks in recv('ioxen-wake:<id>').wait(). The host
// calls the forward/drop/stageMod RPCs and afterwards posts the wake message.
// recv().wait() releases the JS lock while waiting, so RPCs are served while
// the thread is held, and Frida wakes it when the script unloads.
//
// Only one event is held at a time; events that arrive meanwhile are reported
// as observed ("busy").

import { buildFilterContext, isVisible } from './format.js';

export function createDecisionCore(options) {
  const opts = Object.assign({
    send: globalThis.send,
    recv: globalThis.recv,
    threadId: () => Process.getCurrentThreadId(),
    pid: () => Process.id,
    jsThreadId: null,
    captureStack: () => [],
  }, options || {});

  let blockEnabled = true;
  let waiting = false;
  let activeDecisionId = null;
  let activeSupportedMods = [];
  let resumeMode = 'forward';
  let modQueue = [];
  let decisionCounter = 0;
  let eventCounter = 0;
  let ignoreRules = [];
  let focusRules = [];

  function isFiltered(payload) {
    if (!ignoreRules.length && !focusRules.length) return false;
    try {
      return !isVisible(buildFilterContext(payload), ignoreRules, focusRules);
    } catch (_) {
      return false;
    }
  }

  function buildPayload(ev, context) {
    eventCounter += 1;
    return {
      platform: 'ios',
      eventId: 'ev-' + opts.pid() + '-' + eventCounter,
      className: ev.className || null,
      methodName: ev.methodName,
      stackTrace: opts.captureStack(context),
      infoIntent: {
        component: ev.component || null,
        action: ev.action || null,
        data: ev.data || null,
        extras: ev.extras || {},
      },
      attackSurface: ev.attackSurface || null,
      ipc: ev.ipc || {},
    };
  }

  // Returns {mode: 'forward'|'drop', mods: [...], eventId}.
  function process(ev, context) {
    const payload = buildPayload(ev, context);

    let reason = null;
    if (!ev.interceptable) reason = 'observe';
    else if (!blockEnabled) reason = 'intercept_off';
    else if (waiting) reason = 'busy';
    else if (opts.jsThreadId !== null && opts.threadId() === opts.jsThreadId) reason = 'agent_thread';
    else if (isFiltered(payload)) reason = 'filtered';
    const willBlock = reason === null;

    let decisionId = null;
    let operation = null;
    if (willBlock) {
      waiting = true;
      decisionCounter += 1;
      decisionId = 'decision-' + opts.pid() + '-' + decisionCounter;
      activeDecisionId = decisionId;
      activeSupportedMods = ev.mods || [];
      resumeMode = 'forward';
      modQueue = [];
      // Register before sending so an early wake can never be missed.
      operation = opts.recv('ioxen-wake:' + decisionId, function () {});
    }

    payload.decision = { required: willBlock, id: decisionId, reason: reason, mods: ev.mods || [] };
    opts.send(payload);
    if (!willBlock) return { mode: 'forward', mods: [], eventId: payload.eventId };

    try {
      operation.wait();
      return { mode: resumeMode, mods: modQueue.slice(), eventId: payload.eventId };
    } finally {
      waiting = false;
      activeDecisionId = null;
      activeSupportedMods = [];
      resumeMode = 'forward';
      modQueue = [];
    }
  }

  function matches(decisionId) {
    return waiting && (!decisionId || decisionId === activeDecisionId);
  }

  return {
    process: process,

    forward(decisionId) {
      if (!matches(decisionId)) return false;
      resumeMode = 'forward';
      return true;
    },

    drop(decisionId) {
      if (!matches(decisionId)) return false;
      resumeMode = 'drop';
      return true;
    },

    stageMod(type, key, val, extraType, decisionId) {
      if (!matches(decisionId)) {
        opts.send('[!] Error: No event blocked to modify.');
        return false;
      }
      if (activeSupportedMods.indexOf(type) === -1) {
        opts.send('[!] Modification "' + type + '" is not supported for this event');
        return false;
      }
      modQueue.push({ type: type, key: key, val: val, extraType: extraType });
      opts.send('[+] Modification staged: ' + type + (extraType ? ' (' + extraType + ')' : ''));
      return true;
    },

    // Returns the id of the released decision (or null) so the host can wake
    // the held thread.
    interceptOff() {
      blockEnabled = false;
      if (waiting) {
        resumeMode = 'forward';
        return activeDecisionId;
      }
      return null;
    },

    interceptOn() {
      blockEnabled = true;
    },

    setFilters(ignoreList, focusList) {
      ignoreRules = Array.isArray(ignoreList) ? ignoreList : [];
      focusRules = Array.isArray(focusList) ? focusList : [];
      return true;
    },

    isWaiting() {
      return waiting;
    },

    eventCount() {
      return eventCounter;
    },
  };
}
