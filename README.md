# dsh-cyber-redteam

CyberOps runtime for DeepSeek Harness, with masked `/cyber` and authorized
direct-access `/cyber-2` modes, plus a composer **Red Team** toggle.

Renamed from `dsh-cyber-2` (v0.5.0). The command surface, `/cyber-2` wording, and
status contract are unchanged; only the package identity and the harness home
moved.

## Modes

- `/cyber <URL>` — gateway-only mode: the target is reachable only through the
  task-local masked route.
- `/cyber-2 <URL>` — authorized direct-access mode, preserving URL masking.
- `/cyberoff` — revokes all session routes and disables either mode.
- Add another authorized target with `/cyber-2 https://exact-host/path`.

Referenced resources permit routine retrieval, not automatic offensive scope
expansion. Registered URLs stay masked in provider messages and tool results.
Masked origin recovery is not required. Prompt scope is not a network-enforced
allowlist.

## Masking identity

Masking is armed-state driven: a chat that never turned Red Team on keeps every
URL exactly as typed, and nothing is registered for it.

Each masked route also owns its own HTTP listener on its own loopback port, so
two masked URLs never share an origin. The masked base therefore differs per
chat *and* per route:

```
http://127.0.0.1:52104/_cyberops/<token>/...   chat A -> example.com
http://127.0.0.1:52105/_cyberops/<token>/...   chat B -> example.com
http://127.0.0.1:52106/_cyberops/<token>/...   chat A -> api.example.net
```

Every masked route token is minted with a fresh 128-bit nonce mixed into an
HMAC keyed by the install secret and bound to the owning session and origin:

- **One token and one port per chat.** Two conversations that target the same
  origin get different masked URLs *and* different ports, so a URL shown in one
  chat is useless in another.
- **One port per route.** A route's listener only serves that route; a token
  from another route answers 404 on it. Retiring a route closes its listener,
  so a revoked masked URL stops answering at all.
- **Ports survive a restart.** Each route's port is persisted; if another
  process took it, that route falls back to an ephemeral port and persists the
  replacement.
- **One token per activation.** `/cyberoff` (and disarming, hiding, or clearing
  a session) deletes the route. Authorizing the same target again mints a new
  token; a previously leaked URL never starts resolving again.
- **Stable within one activation.** Re-projecting the same user message — which
  `agent/pre-step` does on every step — reuses the live route, so a token never
  rotates mid-turn.
- **Stable across a restart.** The token is persisted in the gateway state, so
  an active chat keeps the exact same masked URL after the harness restarts.

## Red Team toggle

The Web composer renders a **Red Team** chip (seat `conversation.input.right`,
next to the model selector). It is a session-scoped arming switch:

- **Off** (default) — nothing is masked. A pasted URL reaches the model exactly
  as typed, and no route is registered.
- **On** — the CyberOps toolkit section (playbook + tool list) is injected into
  every step for that session, and URLs in that chat are masked.

Arming **authorizes no target**: it changes instruction and masking only.
Targets still require an explicit `/cyber-2 <URL>` before a masked route is
attested. This keeps the plugin's per-target attestation model intact.

Masking follows the armed state, not the presence of a URL:

| Chat state | A pasted URL | `/cyber <URL>` |
| --- | --- | --- |
| Never armed | left as typed | masked, and the chat arms |
| Armed via toggle | masked | masked |
| After `/cyberoff` | left as typed | masked, and the chat arms |

That rule exists because an unarmed chat is an ordinary conversation: rewriting
its links into `127.0.0.1` routes is surprising and makes the pasted URL
unusable. Arming is the explicit opt-in.

The toggle is backed by the `/cyber-mode` command, which is also usable by hand:

```
/cyber-mode status   # report the session's armed state
/cyber-mode on       # arm red-team mode for this session
/cyber-mode off      # disarm it
```

The command returns a line whose prefix is always
`cyber-mode: on|off|unavailable`; the toggle parses that prefix, so keep it when
editing the surrounding copy.

Armed state is persisted per session in the gateway state file, so it survives a
harness restart. New sessions start disarmed.

## State, paths, and configuration

| Concern | Default | Override |
| --- | --- | --- |
| Toolkit root | `$DSH_HOME/toolkits/my-home-server-toolkit`, else `~/.dsh/toolkits/...` | bundle config `toolkitRoot` |
| Gateway state (schema v2: one port per route) | `$DSH_HOME/storages/cyberops-gateway.json`, else `~/.dsh/storages/...` | bundle config `statePath` |
| Private targets | off | bundle config `allowPrivateTargets` |
| Toggle arms direct-access | on | bundle config `armDirectAccess: false` |

State lives under the DeepSeek Harness home. It shares nothing with a Son of
Astra (`~/.soa`) installation: no gateway state, ports, or secrets.

The toolkit is **not** bundled with this plugin. Install a verified toolkit under
`$DSH_HOME/toolkits/my-home-server-toolkit`, or point `toolkitRoot` at yours from
your **profile** patch layer (the bundle patch stays portable, so do not edit it):

```yaml
# ~/.dsh/profiles/<profile>/cordis.patch.yml
- id: cyberops-runtime
  config:
    toolkitRoot: /Users/you/toolkits/my-home-server-toolkit
    allowPrivateTargets: true   # only when the authorized targets are private
```

`config` is replaced wholesale by a later patch, so repeat every key you need.

## Degrading without the toolkit

`verifyToolkit` validates the platform, the checksum manifest, executable
ownership, and permissions. If the toolkit is missing or fails verification, the
plugin **logs a warning and disables itself** instead of throwing: the harness
still boots, and the toggle reports `cyber-mode: unavailable`.

## Install

From this repository's own market index, add it under **Plugins → Discover →
Manage index sources**:

```
https://raw.githubusercontent.com/datawork-technology/dsh-cyber-redteam/main/index.json
```

Or install the commit-pinned spec directly:

```sh
dsh plugin --profile <profile> add "github:datawork-technology/dsh-cyber-redteam"
```

The plugin installs **disarmed** and without a toolkit: the composer toggle
reports `cyber-mode: unavailable` until a verified toolkit is present, and no
target is authorized until you run `/cyber` or `/cyber-2`.

## Publishing a new version

1. Bump `version` in `package.json` and commit.
2. Push, then update `index.json` so its git `source.commit` is the new
   40-hex default-branch SHA, `version` matches `package.json`, and
   `publishTimestamp` is the new Unix seconds.
3. Validate before pushing:

   ```sh
   node -e "const {parseMarketIndex}=await import('@deepseek-ai/dsh-plugin-market-index');parseMarketIndex(JSON.parse(require('fs').readFileSync('index.json','utf8')),'http://localhost/index.json');console.log('ok')" --input-type=module
   ```

## Tests

Run `npm test` to verify the plugin with local fixtures.
