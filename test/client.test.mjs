/**
 * Client-half regression tests.
 *
 * The Red Team chip is a prebuilt browser bundle: it registers a factory on
 * `window.__ModuleLoader__`. These tests build the smallest host shim that can
 * materialize it, then drive the slot's `inject()` control exactly as the
 * composer does. React is stubbed because only the control callback is
 * exercised here — the chip itself is never rendered.
 *
 * The regression this guards: DSH wraps a command outcome as
 * `{ ok, value: { commandId, result: { kind, text } } }`. An earlier revision
 * read `value.text`, which is always undefined, so the chip reported
 * "unavailable" no matter what the host answered.
 */
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import path from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))

/** Materialize the plugin's client bundle and return its module exports. */
async function loadClientModule() {
  const source = await readFile(path.join(here, '..', 'client.js'), 'utf8')
  let registered
  const previousWindow = globalThis.window
  globalThis.window = {
    __ModuleLoader__: {
      load(entry) {
        registered = entry
      },
    },
  }
  try {
    // The bundle is a plain script that calls window.__ModuleLoader__.load().
    Function(source)()
  } finally {
    globalThis.window = previousWindow
  }
  assert.ok(registered, 'client bundle must register a module factory')
  const require = (id) => {
    if (id === 'react' || id === 'react/jsx-runtime') return {}
    throw new Error(`unexpected client require: ${id}`)
  }
  return { entry: registered, exports: registered.factory(require) }
}

/** Capture the slot registration the plugin makes. */
function clientContext(commandResult) {
  const registrations = []
  const dictionaries = []
  const ctx = {
    effect(setup) {
      setup()
    },
    locale: {
      register(namespace, dicts) {
        dictionaries.push({ namespace, dicts })
      },
    },
    slots: {
      inject(name, callback) {
        callback()
      },
      register(options, component) {
        registrations.push({ options, component })
      },
    },
    remote: {
      commands: {
        execute: async () => commandResult,
      },
    },
  }
  return { ctx, registrations, dictionaries }
}

/** Build the exact envelope the DSH commands remote returns. */
function commandEnvelope(text, kind = 'success') {
  return { ok: true, value: { commandId: 'cmd-1', result: { kind, text } } }
}

test('client bundle registers one chip on the conversation input right seat', async () => {
  const { entry, exports } = await loadClientModule()
  assert.equal(entry.id, 'dsh-cyber-redteam')
  const { ctx, registrations, dictionaries } = clientContext(commandEnvelope('cyber-mode: off'))
  exports.apply(ctx)

  assert.equal(registrations.length, 1)
  const [registration] = registrations
  assert.equal(registration.options.name, 'conversation.input.right')
  assert.equal(registration.options.id, 'cyber-mode')
  assert.equal(registration.options.locale, 'cyber')
  assert.equal(typeof registration.options.inject, 'function')
  assert.equal(typeof registration.component, 'function')
  assert.deepEqual(dictionaries.map((d) => d.namespace), ['cyber'])
  assert.deepEqual(Object.keys(dictionaries[0].dicts).sort(), ['en', 'zh'])
})

test('toggle reads the nested command outcome and reports armed state', async () => {
  for (const [text, expected] of [
    ['cyber-mode: on direct-access (20 tools) — armed', 'on'],
    ['cyber-mode: off — disarmed', 'off'],
    ['cyber-mode: unavailable', 'unavailable'],
  ]) {
    const { exports } = await loadClientModule()
    const { ctx, registrations } = clientContext(commandEnvelope(text))
    exports.apply(ctx)
    const { control } = registrations[0].options.inject('session-1')
    assert.equal(await control.status(), expected, `status for ${JSON.stringify(text)}`)
  }
})

test('an armed host reads as on, not unavailable', async () => {
  // The old bug: the host answered `on`, but the chip parsed `value.text`
  // (undefined) and rendered "unavailable".
  const { exports } = await loadClientModule()
  const { ctx, registrations } = clientContext(
    commandEnvelope('cyber-mode: on direct-access'),
  )
  exports.apply(ctx)
  const { control } = registrations[0].options.inject('session-1')
  assert.equal(await control.status(), 'on')
})

test('transport refusals and malformed envelopes stay unavailable', async () => {
  for (const envelope of [
    { ok: false, error: { code: 'denied', message: 'no' } },
    { ok: true, value: undefined },
    { ok: true, value: { commandId: 'cmd-1' } },
    { ok: true, value: { commandId: 'cmd-1', result: {} } },
  ]) {
    const { exports } = await loadClientModule()
    const { ctx, registrations } = clientContext(envelope)
    exports.apply(ctx)
    const { control } = registrations[0].options.inject('session-1')
    assert.equal(await control.status(), 'unavailable')
  }
})

test('arming sends the on and off command lines the host registers', async () => {
  const lines = []
  const registrations = []
  const { exports } = await loadClientModule()
  const ctx = {
    effect(setup) {
      setup()
    },
    locale: { register() {} },
    slots: {
      inject(_name, callback) {
        callback()
      },
      register(options) {
        registrations.push(options)
      },
    },
    remote: {
      commands: {
        execute: async (_sessionId, line) => {
          lines.push(line)
          return commandEnvelope('cyber-mode: off')
        },
      },
    },
  }
  exports.apply(ctx)
  const { control } = registrations[0].inject('session-1')
  await control.set(true)
  await control.set(false)
  assert.deepEqual(lines, ['/cyber-mode on', '/cyber-mode off'])
})
