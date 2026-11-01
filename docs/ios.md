# iOS support

ioxen intercepts inter-process communication (IPC) of iOS processes: events are held in the **Intercept** tab, where you can forward, drop or modify them, and every event is stored in **History** and in the `.ioxen` project.

The captured events are:

| Layer             | What is captured                           | Interceptable                       | Modifiable            |
| ----------------- | ------------------------------------------ | ----------------------------------- | --------------------- |
| **libxpc**        | `xpc_connection_send_message`,             | yes (drop = not sent; sync drop     | XPC dictionary keys   |
| ↳ outgoing        | `…_with_reply`, `…_with_reply_sync`,       | returns                             |                       |
| ↳                 | `xpc_connection_send_notification`         | `XPC_ERROR_CONNECTION_INTERRUPTED`) |                       |
| **libxpc**        | messages delivered to connection event     | yes (drop = handler not called)     | XPC dictionary keys   |
| ↳ incoming        | handlers                                   |                                     |                       |
| **libxpc**        | async reply handlers and sync replies,     | yes                                 | XPC dictionary keys   |
| ↳ replies         | correlated to their request                |                                     |                       |
| **libxpc**        | new peer connections on Mach service       | yes (drop = peer cancelled)         | –                     |
| ↳ listeners       | listeners                                  |                                     |                       |
| **NSXPC**         | `listener:shouldAcceptNewConnection:` on   | yes (drop = connection rejected)    | –                     |
| ↳ listeners       | every delegate                             |                                     |                       |
| **NSXPC**         | remote calls decoded from the              | yes (drop = call not sent)          | arguments (`argN`)    |
| ↳ outgoing calls  | `NSInvocation` before serialization:       |                                     |                       |
| ↳                 | protocol, selector, typed arguments        |                                     |                       |
| **NSXPC**         | reply blocks invoked with the decoded      | yes (drop = reply block not called) | arguments (`argN`)    |
| ↳ replies         | reply objects, linked to their call        |                                     |                       |
| ↳ (opt-in)        |                                            |                                     |                       |
| **NSXPC**         | incoming calls into the exported object,   | yes (drop = method not called)      | arguments (`argN`)    |
| ↳ exported        | with decoded arguments                     |                                     |                       |
| ↳ objects         |                                            |                                     |                       |
| **NSXPC**         | connection creation (service name,         | observed                            | –                     |
| ↳ mapping         | privileged flag), exported/remote          |                                     |                       |
| ↳                 | protocols with their selectors             |                                     |                       |
| **URL schemes /   | `application:openURL:options:`,            | yes (except cold launch and         | URL (`data <url>`)    |
| ↳ universal       | `scene:openURLContexts:`,                  | `canOpenURL:`)                      |                       |
| ↳ links**         | `continueUserActivity`, cold-launch URLs,  |                                     |                       |
| ↳                 | outgoing `openURL:` / `canOpenURL:`        |                                     |                       |
| **Darwin          | `notify_post`, `notify_register_*`         | `notify_post` (drop = not posted)   | –                     |
| ↳ notifications** |                                            |                                     |                       |
| **Web view        | JS→native `WKScriptMessageHandler`         | messages (drop = not delivered)     | –                     |
| ↳ bridges**       | messages (name, body, frame origin),       |                                     |                       |
| ↳ (opt-in)        | bridge registrations, injected user        |                                     |                       |
| ↳                 | scripts, JavaScriptCore exports            |                                     |                       |
| **Web view        | `loadRequest:`, `loadHTMLString:baseURL:`, | yes (drop = not loaded / not run)   | URL; HTML/JS (`arg0`) |
| ↳ loads**         | `loadFileURL:…`, `loadData:…`,             |                                     |                       |
| ↳ (opt-in)        | `evaluateJavaScript:…`,                    |                                     |                       |
| ↳                 | `callAsyncJavaScript:…`, JSContext scripts |                                     |                       |
| **Web view        | `decidePolicyForNavigationAction:` /       | yes (drop = navigation cancelled)   | –                     |
| ↳ navigation**    | `shouldStartLoadWithRequest:`              |                                     |                       |
| ↳ (opt-in)        |                                            |                                     |                       |
| **Web view        | `WKURLSchemeHandler` registrations and     | observed                            | –                     |
| ↳ schemes**       | requests, in-app Safari views,             |                                     |                       |
| ↳ (opt-in)        | `ASWebAuthenticationSession` (OAuth)       |                                     |                       |
| **Network         | `NSURLSession`                             | observed                            | –                     |
| ↳ requests**      | data/upload/download/WebSocket tasks: URL, |                                     |                       |
| ↳ (opt-in)        | method, headers, body preview              |                                     |                       |

The opt-in layers are off in the default configuration. `examples/ios/everything.json` (loaded as **Hook config**) turns on every layer, including NSXPC reply decoding, plus Objective-C hooks for Face ID / Touch ID checks (`LAContext`), app-group shared storage (`NSUserDefaults initWithSuiteName:`, `containerURLForSecurityApplicationGroupIdentifier:`), extension results and clipboard writes (`UIPasteboard set…`). Network requests are only observed; to modify HTTP traffic use an intercepting proxy. Requests made by web views go through WebKit's networking process and appear as web view loads and navigation, not as network requests.

### NSXPC payload decoding

NSXPC serializes calls into `bplist16`, a private Foundation format with no public specification. Instead of re-implementing it from guesses, ioxen decodes NSXPC traffic where Foundation still holds real objects:

- **Outgoing calls** – the private `-[NSXPCConnection _sendInvocation:…]` /
  `_sendSelector:withProxy:…` methods get a passive hook (the original implementation is never replaced), and only after their runtime type encoding matches the expected shape. Arguments are read through the public `NSInvocation`/`NSMethodSignature` API before serialization. On the `_sendSelector:withProxy:argN:` fast path they are object arguments typed from the remote interface's protocol. For the private argument-array path only the selector is reported. Dropping a call suppresses the XPC message it would send.
- **Replies (opt-in)** – with `{"kind": "nsxpc", "feature": "replies"}` in your hook config, the reply block is swapped for a wrapper that reports the decoded reply objects and then calls the original. Replies are correlated with their call. This is off by default because it changes the objects Foundation passes around.
- **Incoming calls** – the exported object's protocol methods are hooked.


## Requirements

- A jailbroken device running `frida-server` (or an app repackaged with the Frida gadget), with the Python `frida` package matching the server version.

## Filters

All filter keys work on iOS events. Two keys are specific to IPC:

- `direction` – `outgoing`, `incoming` or `reply`
- `peer` – the peer process path (or PID when the path is not readable)

```
/filter add ignore component=com.apple.cfprefsd*
/filter add focus direction=incoming
/filter add focus peer=/usr/libexec/*
```

The iOS agent evaluates intercept filters itself before holding a thread, so filtered traffic never waits for a round trip to the host. This matters for chatty system services.

Ready-to-use recipes (hiding system chatter, focusing on attack surface, intercepting without drowning) are in the [filter cheat sheet](ios-filters.md).

## Modifying events

| Command                    | Effect                                                                       |
| -------------------------- | ---------------------------------------------------------------------------- |
| `+x (type) <path>          | Set an XPC key. Types: `string`, `int64`, `uint64`, `bool`, `double`, `data` |
| ↳ <value>`                 | (hex).                                                                       |
| `-x <path>`                | Remove an XPC key.                                                           |
| `+x (type) argN <value>`   | Replace argument *N* of an Objective-C/NSXPC call (strings become            |
| ↳                          | `NSString`, or `NSURL` when the original was a URL; numbers become           |
| ↳                          | `NSNumber` for object arguments).                                            |
| `data <url>`               | Replace the URL of a URL-scheme or universal-link event.                     |


## Attack surface map

`/surface` opens a report that combines:

- **static data** from the target: declared URL schemes, associated domains, user activity types, document types and sharing flags, app extensions (with their extension points), and all entitlements read from the main binary's code signature (app groups, keychain groups, sandbox `mach-lookup` exceptions, private entitlements, ...);
- **observed IPC** from History: XPC listeners and the peers that connected, exported NSXPC interfaces and their selectors, XPC services contacted, URLs received, scheme queries, and Darwin notifications posted or listened to.

`/surface export` writes the same data to `ios_surface_<timestamp>.json`. The static snapshot is stored in the project, so the report also works offline.

## Custom hooks

The **Hook config** file on the Home tab is appended to `config/ios_hooks.json`. Besides the built-in kinds you can intercept any Objective-C method. Patterns with `*` are resolved with Frida's `ApiResolver('objc')`:

```json
[
  {"kind": "objc", "method": "-[MyServiceDelegate handleRequest:reply:]"},
  {"kind": "objc", "method": "-[* processPayload:]", "intercept": false},
  {"kind": "xpc", "function": "xpc_connection_send_message", "enabled": false}
]
```

An entry with the same `kind` and `function`/`feature`/`method` as a built-in one replaces it. Use `"enabled": false` to switch a built-in hook off and `"intercept": false` to observe without holding the thread. See `examples/ios/` for ready-made files.

I added a number of custom configuration examples for xpc only events, no nsxpc, or everything. Please check the directory [examples](examples).

To be sure you, use the [examples/ios/everything.json](examples/ios/everything.json) configuration file and then filter out noise in the **History** tab within ioxen console.

> Monitoring of webviews are not thoroughly tested, so issues may exist.

## How it works

`agent/ios_script.js` hooks the libxpc C API with `Interceptor.replace` and wraps event and reply handler blocks in global blocks whose invoke pointer is a shared `NativeCallback`, PAC-signed on arm64e the same way `frida-objc-bridge` signs block invokes. Messages are decoded with the public libxpc accessors. Objective-C methods are replaced with `ObjC.implement`.

Held threads wait in `recv('ioxen-wake:<id>').wait()`. That call releases the JS lock, so forward/drop/modify RPCs are served while the thread is held. The host posts the wake message after the RPC, and Frida also wakes the thread if the script unloads, so a detach never leaves the target stuck.
