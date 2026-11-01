# iOS filter cheat sheet

A plain iOS app makes hundreds of XPC calls at launch. Most of them are UIKit and Foundation talking to system daemons on the app's behalf, not code the app's developer wrote. Filters cut that down to what matters.

## Where to type them

| Tab           | Filters affect                                     | Command bar                         |
| ------------- | -------------------------------------------------- | ----------------------------------- |
| **History**   | which recorded events are **shown** (everything is | History command bar (`/filter …`)   |
| ↳             | still recorded)                                    | or **Filters** button               |
| **Intercept** | which events are **held** when interception is on  | Intercept command bar (`/filter …`) |
| ↳             | (the rest pass straight through)                   | or **Filters** button               |

`/filter` always applies to the tab you are on. Filters are saved in the project (`.ioxen` file) and come back when you reopen it with `ioxen --project <file>`.

```
/filter list            show active filters with their IDs
/filter remove <id>     delete one
```

The **Filters** dialog also lets you switch individual rules on and off without deleting them.

## Rules of the game

- `ignore` hides what matches; `focus` shows **only** what matches.
- **If any focus rule exists, ignore rules are not applied.** Use one style at a time.
- Keys inside one rule must all match (AND): `focus direction=outgoing component=com.example.*`
- Several focus rules (or several ignore rules) combine with OR.
- Values are globs: `*` any text, `?` one character, `[abc]` one of the characters.
- `set` / `unset` test whether a field has a value at all, e.g. `focus data=set`.

| Key         | iOS meaning                                               | Example                         |
| ----------- | --------------------------------------------------------- | ------------------------------- |
| `component` | XPC service name (or source app for URLs, notification    | `component=com.apple.cfprefsd*` |
| ↳           | name for Darwin notifications)                            |                                 |
| `method`    | hooked function or ObjC method                            | `method=xpc_*`, `method=-[*`    |
| `action`    | NSXPC selector, URL action or XPC error name              | `action=*:*`                    |
| `class`     | module that sent the message, or the ObjC class that      | `class=MyApp`                   |
| ↳           | received the call                                         |                                 |
| `direction` | `outgoing`, `incoming` or `reply`                         | `direction=incoming`            |
| `peer`      | path (or PID) of the process on the other end             | `peer=/usr/libexec/*`           |
| `data`      | URL of URL-scheme / universal-link events                 | `data=myapp://*`                |

## Monitoring all XPC of one app

Everything ioxen records comes from inside the process it attached to. Spawning
`com.example.test` therefore captures all of that app's XPC, both what it sends and
what it receives, without any filter.

1. Home tab: **Device** = your iPhone, **Mode** = Spawn,
   **Target** = `com.example.test`.
2. **Hook config** = `examples/ios/xpc-full.json`. This keeps all libxpc and NSXPC hooks, adds decoded NSXPC replies (off by default) and turns off the non-XPC layers (URL schemes, Darwin notifications).
3. Connect and leave interception **off**. You are only monitoring.
4. In History, trim framework chatter with the ignore recipes below, or zoom in with:
   - `focus direction=incoming`: what other processes send to the app;
   - `focus class=<binary>`: XPC the app's own code calls directly (binary name from the **Class** column or `/surface`);
   - `focus component=com.example.*`: traffic to the vendor's own services.
5. `/surface` for a summary; `/export entries` to save everything as JSON.

Use Spawn rather than Attach. In attach mode, incoming messages on connections created before attaching are not seen.

Not covered by this session:

- **App extensions** (widgets, share extensions, …) run in their own processes. Start them, then attach to them by name in a second ioxen session.
- **The receiving side** of the app's requests lives in the daemon that handles them. To see what the daemon does with a message, attach to that daemon.

## Recipes

### Hide the usual system chatter (ignore style)

```
/filter add ignore component=com.apple.cfprefsd*
/filter add ignore component=com.apple.runningboard*
/filter add ignore component=com.apple.frontboard*
/filter add ignore component=com.apple.lsd*
```

These are services that commonly flood the launch: preferences, app lifecycle and LaunchServices. Look at the **Component** column of your own History to find the noisiest ones for your app and add them the same way.

Heavy handed version, hides every Apple service:

```
/filter add ignore component=com.apple.*
```

Careful: interesting traffic (keychain, networking, file providers) also goes to Apple daemons, so this can hide real findings.

Hide all raw libxpc messages and keep only the decoded events (NSXPC calls and replies, URL handlers, listener decisions, Darwin notifications):

```
/filter add ignore method=xpc_*
```

### Show only what matters (focus style)

Attack surface, i.e. everything other processes send **into** the app:

```
/filter add focus direction=incoming
```

Decoded Objective-C events only (NSXPC calls/replies, URL handlers, listener accept decisions):

```
/filter add focus method=-[*
```

The vendor's own services (replace with the app's prefix):

```
/filter add focus component=com.yourcompany.*
```

Combine them (OR): show incoming traffic *or* anything to the vendor's services:

```
/filter add focus direction=incoming
/filter add focus component=com.yourcompany.*
```

Only messages sent by the app's own code (not by frameworks). Replace `MyApp` with the app's binary name from the **Class** column:

```
/filter add focus class=MyApp
```

URL schemes and universal links only:

```
/filter add focus data=set
```

NSXPC calls by selector (anything with a `:` in it):

```
/filter add focus action=*:*
```

### Intercepting without drowning

Interception is off by default. Before switching it on (Intercept tab → **Intercept off** button), add **intercept** filters so only interesting events are held. For example, from the Intercept command bar:

```
/filter add focus direction=incoming
/filter add focus component=com.yourcompany.*
```

Everything else is still recorded in History, but passes through without waiting for you.

See [ios.md](ios.md) for the full iOS guide.
