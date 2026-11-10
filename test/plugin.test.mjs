import { createHash } from 'node:crypto'
import { chmod, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import assert from 'node:assert/strict'

import {
  CorruptedRouteCircuit,
  CyberOpsGateway,
  apply,
  cyberOpsPrompt,
  projectMessage,
  verifyToolkit,
} from '../index.js'

/** A valid persisted identity key: base64url of exactly 32 bytes. */
const IDENTITY_KEY = Buffer.alloc(32, 7).toString('base64url')

function pluginContext() {
  const sections = new Map()
  const contexts = new Map()
  const hooks = new Map()
  const cleanups = []
  const commands = new Map()
  const ctx = {
    effect(setup) {
      cleanups.push(setup())
    },
    inject(_waitFor, callback) {
      callback({
        commands: {
          register(definition) {
            commands.set(definition.name, definition)
          },
        },
      })
    },
    systemPrompt: {
      section(definition) {
        sections.set(definition.name, definition.text)
      },
      context(definition) {
        contexts.set(definition.name, definition.text)
      },
    },
    on(name, handler) {
      hooks.set(name, handler)
    },
    tools: {
      guard() {},
    },
    logger() {
      return { info() {}, warn() {} }
    },
  }
  return {
    ctx,
    sections,
    contexts,
    hooks,
    commands,
    async close() {
      for (const cleanup of cleanups.reverse()) await cleanup?.()
    },
  }
}

test('builds CyberOps prompt only from the verified toolkit', () => {
  const prompt = cyberOpsPrompt({
    bundleVersion: 'test.1',
    tools: ['cyberops-probe'],
    playbook: 'Fixture playbook.',
  })
  assert.match(prompt, /test\.1/u)
  assert.match(prompt, /cyberops-probe/u)
  assert.match(prompt, /Fixture playbook\./u)
})

function digest(content) {
  return createHash('sha256').update(content).digest('hex')
}

async function fixture() {
  const root = await mkdtemp(path.join(os.tmpdir(), 'dsh-cyberops-'))
  await mkdir(path.join(root, 'bin'))
  const playbook = 'Use the probe only for an authorized local fixture.\n'
  const executable = '#!/bin/sh\nprintf cyberops-ok\n'
  const manifest = `${JSON.stringify({
    schemaVersion: 1,
    bundleVersion: 'test.1',
    platform: `${process.platform}-${process.arch}`,
    tools: [{
      name: 'cyberops-probe',
      version: '1',
      executable: 'bin/cyber-probe',
      category: 'Test',
      use: 'Verify the fixture.',
    }],
  }, null, 2)}\n`

  await writeFile(path.join(root, 'PLAYBOOK.md'), playbook)
  await writeFile(path.join(root, 'manifest.json'), manifest)
  await writeFile(path.join(root, 'bin/cyber-probe'), executable)
  await chmod(path.join(root, 'bin/cyber-probe'), 0o700)
  await writeFile(path.join(root, 'checksums.sha256'), [
    `${digest(playbook)}  ./PLAYBOOK.md`,
    `${digest(manifest)}  ./manifest.json`,
    `${digest(executable)}  ./bin/cyber-probe`,
    '',
  ].join('\n'))
  return root
}

test('plugin prompt is opt-in through /cyber and /cyberoff', async (t) => {
  const root = await fixture()
  const runtime = pluginContext()
  t.after(async () => {
    await runtime.close()
    await rm(root, { recursive: true, force: true })
  })
  await apply(runtime.ctx, {
    toolkitRoot: root,
    statePath: path.join(root, 'gateway-state.json'),
  })

  const agent = { id: 'plugin-session' }
  const section = runtime.sections.get('cyberops:toolkit')
  const context = runtime.contexts.get('cyberops:targets')
  const preStep = runtime.hooks.get('agent/pre-step')
  const enter = (text) => preStep(
    { agent, turn: text },
    async () => ({
      kind: 'enter',
      messages: [{
        id: `message:${text}`,
        role: 'user',
        source: { kind: 'user' },
        content: [{ type: 'text', text }],
      }],
    }),
  )

  assert.equal(section({ agent }), '')
  assert.equal(context({ agent }), '')

  await enter('Read https://example.com as a normal reference.')
  assert.equal(section({ agent }), '')
  assert.equal(context({ agent }), '')

  const activation = await enter('/cyber https://example.com')
  assert.match(section({ agent }), /## CyberOps toolkit/u)
  assert.match(context({ agent }), /authorized target/u)
  assert.match(activation.messages.at(-1).content[0].text, /## CyberOps toolkit/u)

  // Format v4 admits only producer-owned sources: an object with a non-empty
  // `kind` that is not the retired `plugin` wrapper. Anything else aborts the turn.
  for (const message of activation.messages) {
    assert.equal(typeof message.source, 'object')
    assert.equal(typeof message.source.kind, 'string')
    assert.notEqual(message.source.kind, '')
    assert.notEqual(message.source.kind, 'plugin')
  }
  assert.equal(activation.messages.at(-1).source.kind, 'plugin:dsh-cyber-redteam')

  await enter('/cyberoff')
  assert.equal(section({ agent }), '')
  assert.equal(context({ agent }), '')
})

test('verifies a complete owned toolkit', async (t) => {
  const root = await fixture()
  t.after(() => rm(root, { recursive: true, force: true }))
  const toolkit = await verifyToolkit(root)
  assert.equal(toolkit.bundleVersion, 'test.1')
  assert.deepEqual(toolkit.tools, ['cyberops-probe'])
  assert.equal(toolkit.playbook, await readFile(path.join(root, 'PLAYBOOK.md'), 'utf8'))
})

test('fails closed when a checksummed file changes', async (t) => {
  const root = await fixture()
  t.after(() => rm(root, { recursive: true, force: true }))
  await writeFile(path.join(root, 'PLAYBOOK.md'), 'tampered\n')
  await assert.rejects(() => verifyToolkit(root), /checksum failed: PLAYBOOK\.md/)
})

test('rejects a toolkit for another platform', async (t) => {
  const root = await fixture()
  t.after(() => rm(root, { recursive: true, force: true }))
  await assert.rejects(
    () => verifyToolkit(root, { platform: 'linux', arch: 'x64' }),
    /cannot run on linux-x64/,
  )
})

test('masks an explicitly authorized URL without exposing its origin', async (t) => {
  const gateway = new CyberOpsGateway()
  await gateway.start()
  t.after(() => gateway.close())

  const original = 'Please test /cyber https://example.com/admin?q=1.'
  const projected = gateway.projectPrompt('session-a', original).text
  assert.doesNotMatch(projected, /example\.com/u)
  assert.match(projected, new RegExp(`^Please test /cyber ${gateway.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/_cyberops/`))
  assert.match(gateway.context('session-a'), /authorized target/u)
  assert.doesNotMatch(gateway.context('session-a'), /example\.com/u)
})

test('does not activate CyberOps for referenced URLs', async (t) => {
  const gateway = new CyberOpsGateway()
  await gateway.start()
  t.after(() => gateway.close())

  gateway.projectPrompt('session-b', 'Audit https://example.com; use https://docs.example.net only as a reference.')
  assert.equal(gateway.context('session-b'), '')
})

test('projects user messages before they enter the model step', async (t) => {
  const gateway = new CyberOpsGateway()
  await gateway.start()
  t.after(() => gateway.close())
  const message = Object.freeze({
    id: 'message-1',
    role: 'user',
    source: { kind: 'user' },
    content: Object.freeze([{ type: 'text', text: 'https://example.com/private' }]),
  })

  const projected = projectMessage(gateway, 'session-c', message)
  assert.equal(projected.id, message.id)
  assert.notEqual(projected, message)
  assert.doesNotMatch(projected.content[0].text, /example\.com/u)
  assert.equal(Object.isFrozen(projected), true)
})

test('guard stays non-blocking when blocking policy is disabled', async (t) => {
  const gateway = new CyberOpsGateway()
  await gateway.start()
  t.after(() => gateway.close())
  gateway.projectPrompt('session-d', '/cyber https://example.com')

  assert.equal(
    gateway.guardReason('session-d', 'bash', { command: 'curl https://example.com' }),
    undefined,
  )
  assert.equal(
    gateway.guardReason('session-d', 'web_fetch', { url: 'https://unrelated.example/path' }),
    undefined,
  )
  assert.equal(
    gateway.guardReason('session-d', 'bash', { command: 'nmap unrelated.example' }),
    undefined,
  )
  assert.match(gateway.context('session-d'), /authorized target/u)
})

test('corrupted-route circuit ignores valid calls and resets on a new turn', () => {
  const circuit = new CorruptedRouteCircuit()
  const agent = {}

  assert.equal(circuit.beginTurn(agent, 'turn-a'), false)
  assert.equal(circuit.record(agent).open, false)
  circuit.clear(agent)
  assert.equal(circuit.record(agent).count, 1)
  assert.equal(circuit.record(agent).open, false)
  assert.equal(circuit.record(agent).open, true)
  assert.equal(circuit.beginTurn(agent, 'turn-a'), true)
  assert.equal(circuit.beginTurn(agent, 'turn-b'), false)
})

test('local gateway forwards authorized requests and masks redirects', async (t) => {
  const upstream = http.createServer((request, response) => {
    if (request.url === '/redirect') {
      response.writeHead(302, { location: '/next' })
      return response.end()
    }
    response.writeHead(200, { 'content-type': 'text/plain' })
    response.end(`upstream:${request.method}:${request.url}`)
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => upstream.close(resolve)))

  const gateway = new CyberOpsGateway({ allowPrivateTargets: true })
  await gateway.start()
  t.after(() => gateway.close())
  const upstreamPort = upstream.address().port
  const alias = gateway.projectPrompt(
    'session-e',
    `/cyber http://127.0.0.1:${upstreamPort}/redirect`,
  ).text.replace('/cyber ', '')

  const redirected = await fetch(alias, { redirect: 'manual' })
  assert.equal(redirected.status, 302)
  assert.match(redirected.headers.get('location'), new RegExp(`^${gateway.origin.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/_cyberops/`))
  assert.doesNotMatch(redirected.headers.get('location'), new RegExp(String(upstreamPort)))

  const destination = new URL(redirected.headers.get('location'), gateway.origin)
  const result = await fetch(destination)
  assert.equal(await result.text(), 'upstream:GET:/next')
})

test('local gateway supports hostname lookup when Node requests all addresses', async (t) => {
  const upstream = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' })
    response.end('hostname-target-ok')
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => upstream.close(resolve)))

  const gateway = new CyberOpsGateway({ allowPrivateTargets: true })
  await gateway.start()
  t.after(() => gateway.close())
  const upstreamPort = upstream.address().port
  const alias = gateway.projectPrompt(
    'hostname-session',
    `/cyber http://localhost:${upstreamPort}/health`,
  ).text.replace('/cyber ', '')

  const response = await fetch(alias)
  assert.equal(response.status, 200)
  assert.equal(await response.text(), 'hostname-target-ok')
})

test('an authorized masked route survives a gateway restart', async (t) => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'dsh-cyberops-state-'))
  const statePath = path.join(stateRoot, 'gateway.json')
  t.after(() => rm(stateRoot, { recursive: true, force: true }))

  const upstream = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' })
    response.end('persistent-target-ok')
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => upstream.close(resolve)))

  const upstreamPort = upstream.address().port
  const first = new CyberOpsGateway({ allowPrivateTargets: true, statePath })
  await first.start()
  const alias = first.projectPrompt(
    'persistent-session',
    `/cyber http://127.0.0.1:${upstreamPort}/health`,
  ).text.replace('/cyber ', '')
  assert.equal(await (await fetch(alias)).text(), 'persistent-target-ok')
  await first.close()

  const second = new CyberOpsGateway({ allowPrivateTargets: true, statePath })
  await second.start()
  t.after(() => second.close())

  assert.equal(second.origin, new URL(alias).origin)
  assert.equal(await (await fetch(alias)).text(), 'persistent-target-ok')
  assert.match(second.context('persistent-session'), /authorized target/u)
})

test('a taken persisted port falls back to an ephemeral one instead of failing boot', async (t) => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'dsh-cyberops-port-'))
  const statePath = path.join(stateRoot, 'gateway.json')
  t.after(() => rm(stateRoot, { recursive: true, force: true }))

  // Another process owns the port this gateway recorded on its previous boot.
  const squatter = http.createServer()
  await new Promise((resolve) => squatter.listen(0, '127.0.0.1', resolve))
  const takenPort = squatter.address().port
  t.after(() => new Promise((resolve) => squatter.close(resolve)))

  await writeFile(statePath, JSON.stringify({
    version: 1,
    port: takenPort,
    secret: IDENTITY_KEY,
    sessions: [],
  }))

  const gateway = new CyberOpsGateway({ allowPrivateTargets: true, statePath })
  await gateway.start()
  t.after(() => gateway.close())

  assert.notEqual(new URL(gateway.origin).port, String(takenPort))
  // The replacement port is persisted, so the next boot is stable again.
  const persisted = JSON.parse(await readFile(statePath, 'utf8'))
  assert.equal(persisted.port, Number(new URL(gateway.origin).port))
})

test('a non-EADDRINUSE listen failure still surfaces', async (t) => {
  const stateRoot = await mkdtemp(path.join(os.tmpdir(), 'dsh-cyberops-bind-'))
  const statePath = path.join(stateRoot, 'gateway.json')
  t.after(() => rm(stateRoot, { recursive: true, force: true }))

  // Port 1 is privileged: binding it as an unprivileged user is EACCES, not a
  // stale-port collision, so the failure must not be swallowed.
  await writeFile(statePath, JSON.stringify({
    version: 1,
    port: 1,
    secret: IDENTITY_KEY,
    sessions: [],
  }))

  const gateway = new CyberOpsGateway({ allowPrivateTargets: true, statePath })
  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    t.skip('running as root; port 1 is bindable')
    return
  }
  await assert.rejects(() => gateway.start(), (error) => error.code === 'EACCES')
})

test('an unavailable destination returns an actionable masked diagnosis', async (t) => {
  const reservation = http.createServer()
  await new Promise((resolve) => reservation.listen(0, '127.0.0.1', resolve))
  const unavailablePort = reservation.address().port
  await new Promise((resolve) => reservation.close(resolve))

  const gateway = new CyberOpsGateway({ allowPrivateTargets: true })
  await gateway.start()
  t.after(() => gateway.close())
  const alias = gateway.projectPrompt(
    'unavailable-session',
    `/cyber http://127.0.0.1:${unavailablePort}/health`,
  ).text.replace('/cyber ', '')

  const response = await fetch(alias)
  const body = await response.text()
  assert.equal(response.status, 502)
  assert.equal(response.headers.get('x-cyberops-error'), 'upstream-connect-refused')
  assert.match(body, /masked route is valid/u)
  assert.match(body, /transient upstream failure/iu)
  assert.match(body, /retry this exact masked URL/iu)
  assert.match(body, /bounded backoff/iu)
  assert.doesNotMatch(body, /do not (?:retry|start a background poll)/iu)
  assert.doesNotMatch(body, new RegExp(String(unavailablePort)))
  const context = gateway.context('unavailable-session')
  assert.match(context, /bounded, spaced background check is allowed/iu)
  assert.match(context, /does not require ending the task or marking a goal blocked/iu)
})

test('cyber2 retains masking, persists direct mode, switches back and revokes routes', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'cyber2-state-'))
  const statePath = path.join(root, 'state.json')
  let gateway = new CyberOpsGateway({ statePath })
  t.after(async () => { await gateway.close(); await rm(root, { recursive: true, force: true }) })
  await gateway.start()
  const masked = gateway.projectPrompt('cyber2-session', '/cyber-2 https://example.com/proof').text
  assert.doesNotMatch(masked, /example\.com/)
  assert.match(masked, /\/_cyberops\//)
  assert.equal(gateway.sessionState('cyber2-session').directAccess, true)
  assert.match(gateway.context('cyber2-session'), /Direct requests to authorized/)
  assert.doesNotMatch(gateway.context('cyber2-session'), /Never infer, recover, print/)
  assert.equal(gateway.guardReason('cyber2-session', 'web_fetch', { url: 'https://example.com/proof' }), undefined)
  assert.doesNotMatch(cyberOpsPrompt({ tools: [], playbook: '' }, true), /Do not bypass/)
  await gateway.close()
  gateway = new CyberOpsGateway({ statePath })
  await gateway.start()
  assert.equal(gateway.sessionState('cyber2-session').directAccess, true)
  assert.equal(gateway.providerText('cyber2-session', 'https://example.com/proof'), masked.replace('/cyber-2 ', ''))
  gateway.projectPrompt('cyber2-session', '/cyber https://example.com')
  assert.equal(gateway.sessionState('cyber2-session').directAccess, false)
  assert.match(gateway.context('cyber2-session'), /Never infer, recover, print/)
  gateway.projectPrompt('cyber2-session', '/cyber-2 https://example.com')
  gateway.projectPrompt('cyber2-session', '/cyberoff')
  assert.equal(gateway.context('cyber2-session'), '')
  assert.equal((await fetch(masked.replace('/cyber-2 ', ''))).status, 404)
})

/** The opaque token segment of a masked task URL. */
function tokenOf(alias) {
  return new URL(alias).pathname.split('/')[2]
}

test('every chat mints its own masked route for the same origin', async (t) => {
  const gateway = new CyberOpsGateway()
  await gateway.start()
  t.after(() => gateway.close())

  const sessions = ['chat-a', 'chat-b', 'chat-c', 'chat-d']
  const tokens = new Map()
  for (const session of sessions) {
    const projected = gateway.projectPrompt(session, '/cyber-2 https://example.com/app').text
    const token = tokenOf(projected.replace('/cyber-2 ', ''))
    assert.match(token, /^[A-Za-z0-9_-]{24}$/u)
    tokens.set(session, token)
  }
  assert.equal(new Set(tokens.values()).size, sessions.length, 'tokens must be unique per chat')

  // A chat's prompt exposes only its own token, never a sibling chat's.
  for (const session of sessions) {
    const context = gateway.context(session)
    for (const [other, token] of tokens) {
      if (other === session) assert.match(context, new RegExp(token))
      else assert.doesNotMatch(context, new RegExp(token))
    }
  }
})

test('a re-activation mints a new token instead of resurrecting the revoked one', async (t) => {
  const upstream = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/plain' })
    response.end('revoke-target-ok')
  })
  await new Promise((resolve) => upstream.listen(0, '127.0.0.1', resolve))
  t.after(() => new Promise((resolve) => upstream.close(resolve)))
  const port = upstream.address().port

  const gateway = new CyberOpsGateway({ allowPrivateTargets: true })
  await gateway.start()
  t.after(() => gateway.close())

  const first = gateway.projectPrompt('revoke-chat', `/cyber-2 http://127.0.0.1:${port}/one`).text
    .replace('/cyber-2 ', '')
  assert.equal(await (await fetch(first)).text(), 'revoke-target-ok')

  gateway.projectPrompt('revoke-chat', '/cyberoff')
  assert.equal((await fetch(first)).status, 404, 'revoked token must stop resolving')

  const second = gateway.projectPrompt('revoke-chat', `/cyber-2 http://127.0.0.1:${port}/one`).text
    .replace('/cyber-2 ', '')
  assert.notEqual(tokenOf(first), tokenOf(second), 'a new activation must mint a new token')
  assert.equal((await fetch(first)).status, 404, 'the old token must stay dead')
  assert.equal(await (await fetch(second)).text(), 'revoke-target-ok')
})

test('re-projecting one activation keeps the same masked route', async (t) => {
  const gateway = new CyberOpsGateway()
  await gateway.start()
  t.after(() => gateway.close())

  const prompt = 'Please test /cyber https://example.com/admin.'
  const once = gateway.projectPrompt('stable-chat', prompt).text
  const twice = gateway.projectPrompt('stable-chat', prompt).text
  assert.equal(once, twice, 'agent/pre-step re-projects history, so a route must be stable within one activation')
})

test('a new chat after a restart still gets a token of its own', async (t) => {
  const root = await mkdtemp(path.join(os.tmpdir(), 'dsh-cyberops-unique-'))
  const statePath = path.join(root, 'gateway.json')

  const first = new CyberOpsGateway({ statePath })
  await first.start()
  const before = first.projectPrompt('persisted-chat', '/cyber-2 https://example.com/x').text
    .replace('/cyber-2 ', '')
  await first.close()

  const second = new CyberOpsGateway({ statePath })
  await second.start()
  // Close before removing the state directory: close() flushes a queued write.
  t.after(async () => {
    await second.close()
    await rm(root, { recursive: true, force: true })
  })

  // The active chat keeps its route across the restart...
  assert.equal(second.providerText('persisted-chat', 'https://example.com/x'), before)
  // ...while a different chat never inherits that token.
  const other = second.projectPrompt('fresh-chat', '/cyber-2 https://example.com/x').text
    .replace('/cyber-2 ', '')
  assert.notEqual(tokenOf(other), tokenOf(before))
})
