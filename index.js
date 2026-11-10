import { createHash, randomUUID } from 'node:crypto'
import { createReadStream } from 'node:fs'
import {
  access,
  constants,
  lstat,
  readFile,
  realpath,
  stat,
} from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'

import {
  CORRUPTED_ROUTE_REASON_PREFIX,
  CyberOpsGateway,
} from './siteproxy.js'

export const name = 'cyberops-runtime'
export const inject = ['systemPrompt', 'tools']

const REQUIRED_FILES = ['manifest.json', 'PLAYBOOK.md']

function assertObject(value, message) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(message)
  }
}

function parseManifest(value) {
  assertObject(value, 'CyberOps manifest must be an object')
  if (value.schemaVersion !== 1) {
    throw new Error(`Unsupported CyberOps manifest schema: ${String(value.schemaVersion)}`)
  }
  if (typeof value.bundleVersion !== 'string' || value.bundleVersion.length === 0) {
    throw new Error('CyberOps manifest is missing bundleVersion')
  }
  if (typeof value.platform !== 'string' || value.platform.length === 0) {
    throw new Error('CyberOps manifest is missing platform')
  }
  if (!Array.isArray(value.tools) || value.tools.length === 0) {
    throw new Error('CyberOps manifest has no tools')
  }

  const tools = value.tools.map((candidate) => {
    assertObject(candidate, 'CyberOps manifest contains an invalid tool')
    for (const key of ['name', 'version', 'executable', 'category', 'use']) {
      if (typeof candidate[key] !== 'string' || candidate[key].trim() === '') {
        throw new Error(`CyberOps tool has an invalid ${key}`)
      }
    }
    return candidate
  })

  if (new Set(tools.map((tool) => tool.name)).size !== tools.length) {
    throw new Error('CyberOps manifest contains duplicate tool names')
  }

  return {
    schemaVersion: 1,
    bundleVersion: value.bundleVersion,
    platform: value.platform,
    tools,
  }
}

function normalizeRelative(relativePath) {
  const withoutPrefix = relativePath.replace(/^\*?\.\//, '')
  const normalized = path.normalize(withoutPrefix)
  if (
    !withoutPrefix ||
    path.isAbsolute(withoutPrefix) ||
    normalized === '..' ||
    normalized.startsWith(`..${path.sep}`)
  ) {
    throw new Error(`CyberOps toolkit path is not local: ${relativePath}`)
  }
  return normalized
}

async function containedFile(root, relativePath) {
  const normalized = normalizeRelative(relativePath)
  const candidate = path.join(root, normalized)
  const resolved = await realpath(candidate)
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    throw new Error(`CyberOps toolkit path escapes its root: ${relativePath}`)
  }
  if (!(await stat(resolved)).isFile()) {
    throw new Error(`CyberOps toolkit path is not a file: ${relativePath}`)
  }
  return { normalized, candidate, resolved }
}

async function sha256(filePath) {
  const hash = createHash('sha256')
  for await (const chunk of createReadStream(filePath)) hash.update(chunk)
  return hash.digest('hex')
}

function parseChecksums(content) {
  const checksums = new Map()
  for (const line of content.split(/\r?\n/)) {
    if (!line) continue
    const match = /^([a-f0-9]{64})\s+(.+)$/.exec(line)
    if (!match) throw new Error('CyberOps checksum manifest contains an invalid entry')
    const relativePath = normalizeRelative(match[2])
    if (checksums.has(relativePath)) {
      throw new Error(`CyberOps checksum manifest contains a duplicate entry: ${relativePath}`)
    }
    checksums.set(relativePath, match[1])
  }
  if (checksums.size === 0) throw new Error('CyberOps checksum manifest is empty')
  return checksums
}

export async function verifyToolkit(toolkitPath, options = {}) {
  const root = await realpath(toolkitPath)
  const manifestPath = await containedFile(root, 'manifest.json')
  const manifest = parseManifest(JSON.parse(await readFile(manifestPath.resolved, 'utf8')))
  const expectedPlatform = `${options.platform ?? process.platform}-${options.arch ?? process.arch}`
  if (manifest.platform !== expectedPlatform) {
    throw new Error(`CyberOps toolkit platform ${manifest.platform} cannot run on ${expectedPlatform}`)
  }

  const checksumPath = await containedFile(root, 'checksums.sha256')
  const checksums = parseChecksums(await readFile(checksumPath.resolved, 'utf8'))
  for (const required of REQUIRED_FILES) {
    if (!checksums.has(required)) {
      throw new Error(`CyberOps checksum manifest is missing ${required}`)
    }
  }

  for (const [relativePath, expected] of checksums) {
    const file = await containedFile(root, relativePath)
    if (await sha256(file.resolved) !== expected) {
      throw new Error(`CyberOps toolkit checksum failed: ${relativePath}`)
    }
  }

  const expectedUid = options.uid ?? process.getuid?.()
  for (const tool of manifest.tools) {
    const executable = await containedFile(root, tool.executable)
    const linkInfo = await lstat(executable.candidate)
    if (linkInfo.isSymbolicLink()) {
      throw new Error(`CyberOps executable must not be a symlink: ${tool.executable}`)
    }
    const executableInfo = await stat(executable.resolved)
    if (expectedUid !== undefined && executableInfo.uid !== expectedUid) {
      throw new Error(`CyberOps executable is not owned by the current user: ${tool.executable}`)
    }
    if ((executableInfo.mode & 0o022) !== 0) {
      throw new Error(`CyberOps executable is group- or world-writable: ${tool.executable}`)
    }
    await access(executable.resolved, constants.X_OK)
    if (!checksums.has(normalizeRelative(tool.executable))) {
      throw new Error(`CyberOps executable is missing from checksums: ${tool.executable}`)
    }
  }

  const playbookPath = (await containedFile(root, 'PLAYBOOK.md')).resolved
  return {
    root,
    bin: path.join(root, 'bin'),
    playbookPath,
    playbook: await readFile(playbookPath, 'utf8'),
    bundleVersion: manifest.bundleVersion,
    tools: manifest.tools.map((tool) => tool.name),
  }
}

function installEnvironment(values) {
  const previous = new Map()
  for (const [key, value] of Object.entries(values)) {
    previous.set(key, {
      existed: Object.hasOwn(process.env, key),
      value: process.env[key],
    })
    process.env[key] = value
  }

  return () => {
    for (const [key, state] of previous) {
      if (state.existed) process.env[key] = state.value
      else delete process.env[key]
    }
  }
}

function freeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const item of Object.values(value)) freeze(item)
  return Object.freeze(value)
}

function cyberOpsContextMessage(text) {
  return freeze({
    id: randomUUID(),
    role: 'user',
    content: [{ type: 'text', text }],
    source: {
      kind: 'plugin:dsh-cyber-redteam',
      form: 'notice',
      summary: 'CyberOps masked target routes updated',
    },
  })
}

export function cyberOpsPrompt(toolkit, directAccess = false) {
  return [
    '## CyberOps toolkit',
    '',
    `Verified CyberOps toolkit ${toolkit.bundleVersion} is available on PATH: ${toolkit.tools.join(', ')}.`,
    'Use it only for systems owned by the user or targets the user explicitly authorizes. The active DeepSeek Harness approval and sandbox policies remain authoritative.',
    'Use `/cyber <URL>` for gateway-only mode or `/cyber-2 <URL>` for authorized direct-access mode with masking retained. `/cyberoff` deactivates either mode.',
    directAccess
      ? 'Cyber-2: the gateway is preferred, not exclusive. Direct access is permitted within the user-authorized targets and activities. Masking is a presentation feature, not a gateway-only authorization boundary. Proceed without repeated approval within the agreed scope.'
      : 'In masked mode, treat only routes labelled `authorized target` as offensive-testing scope. Do not bypass the task-local gateway.',
    '',
    toolkit.playbook,
  ].join('\n')
}

export async function projectMessage(gateway, sessionId, message) {
  let changed = false
  const userAuthored = message.source?.kind === 'user'
  const content = []
  for (const block of message.content) {
    if (block.type !== 'text') {
      content.push(block)
      continue
    }
    const projected = userAuthored
      ? (await gateway.projectPrompt(sessionId, block.text)).text
      : gateway.providerText(sessionId, block.text)
    if (projected === block.text) {
      content.push(block)
      continue
    }
    changed = true
    content.push({ ...block, text: projected })
  }
  return changed ? freeze({ ...message, content }) : message
}

export class CorruptedRouteCircuit {
  #states = new WeakMap()

  beginTurn(agent, turn) {
    const state = this.#states.get(agent)
    if (!state || state.turn !== turn) {
      this.#states.set(agent, { turn, count: 0, open: false })
      return false
    }
    return state.open
  }

  record(agent) {
    const state = this.#states.get(agent) ?? { turn: undefined, count: 0, open: false }
    state.count += 1
    state.open = state.count >= 3
    this.#states.set(agent, state)
    return { count: state.count, open: state.open }
  }

  clear(agent) {
    const state = this.#states.get(agent)
    if (!state) return
    state.count = 0
    state.open = false
  }
}

function projectContent(gateway, sessionId, content) {
  let changed = false
  const projected = content.map((block) => {
    if (block.type !== 'text') return block
    const text = gateway.providerText(sessionId, block.text)
    if (text === block.text) return block
    changed = true
    return { ...block, text }
  })
  return changed ? projected : content
}

/** Harness home this plugin keeps state under: `$DSH_HOME`, else `~/.dsh`. */
export function harnessHome(env = process.env) {
  const configured = env.DSH_HOME
  if (typeof configured === 'string' && configured.trim() !== '') return path.resolve(configured)
  return path.join(os.homedir(), '.dsh')
}

/** Human command that arms or disarms red-team mode for one session. */
export const CYBER_MODE_COMMAND = 'cyber-mode'

/** Toolkit location used when the bundle does not configure one. */
export const DEFAULT_TOOLKIT_RELATIVE = path.join('toolkits', 'my-home-server-toolkit')

/**
 * Machine-parseable status line for the composer toggle and for humans. The
 * `cyber-mode: on|off|unavailable` prefix is a stable contract: the Web toggle
 * matches it, so keep the prefix when editing the copy around it.
 * @param state - `'on'`, `'off'`, or `'unavailable'`.
 * @param details - optional tool count and direct-access flag.
 * @returns the status line.
 */
export function cyberModeText(state, details = {}) {
  if (state === 'unavailable') return 'cyber-mode: unavailable'
  if (state === 'on') {
    const suffix = details.direct === false ? '' : ' direct-access'
    const tools = Number.isSafeInteger(details.tools) ? ` (${details.tools} tools)` : ''
    return `cyber-mode: on${suffix}${tools} — CyberOps red-team mode is armed for this session. Arming authorizes no target: name a target with /cyber-2 <URL> before offensive work.`
  }
  return 'cyber-mode: off — CyberOps red-team mode is disarmed for this session.'
}

export async function apply(ctx, config = {}) {
  const home = harnessHome()
  const toolkitRoot = typeof config.toolkitRoot === 'string' && config.toolkitRoot.trim() !== ''
    ? config.toolkitRoot
    : path.join(home, DEFAULT_TOOLKIT_RELATIVE)
  const statePath = typeof config.statePath === 'string' && config.statePath.trim() !== ''
    ? config.statePath
    : path.join(home, 'storages', 'cyberops-gateway.json')

  let toolkit
  let unavailableReason = ''
  try {
    toolkit = await verifyToolkit(toolkitRoot)
  } catch (error) {
    unavailableReason = error instanceof Error ? error.message : String(error)
  }

  // A missing or invalid toolkit must never take the whole harness down: this
  // bundle is a default, so it degrades to a disabled mode that the composer
  // toggle can still report.
  if (toolkit === undefined) {
    ctx.logger?.('cyberops').warn(
      'CyberOps toolkit unavailable at %s (%s); red-team mode stays disabled for this boot',
      toolkitRoot,
      unavailableReason,
    )
    ctx.inject(['commands'], (commandCtx) => {
      commandCtx.commands.register({
        name: CYBER_MODE_COMMAND,
        description: 'Arm or disarm CyberOps red-team mode for this session',
        input: { hint: '[on|off|status]' },
        handler: () => ({
          kind: 'error',
          text: `${cyberModeText('unavailable')} — toolkit at ${toolkitRoot} could not be verified: ${unavailableReason}`,
        }),
      })
    })
    return
  }

  const gateway = new CyberOpsGateway({
    allowPrivateTargets: config.allowPrivateTargets === true,
    statePath,
  })
  await gateway.start()
  const corruptedRouteCircuit = new CorruptedRouteCircuit()
  const existingPath = process.env.PATH ?? ''
  const pathEntries = existingPath.split(path.delimiter).filter(Boolean)
  const effectivePath = pathEntries.includes(toolkit.bin)
    ? existingPath
    : [toolkit.bin, ...pathEntries].join(path.delimiter)

  ctx.effect(() => installEnvironment({
    PATH: effectivePath,
    DEEPEX_EXECUTION_TARGET_ID: 'my-home-server',
    DEEPEX_EXECUTION_TARGET_KIND: 'logical-local',
    DEEPEX_EXECUTION_TARGET_NAME: 'DeepSeek Harness CyberOps',
    DEEPEX_EXECUTION_TARGET_BIN: toolkit.bin,
    DEEPEX_EXECUTION_TARGET_TOOLS: toolkit.tools.join(','),
    DEEPEX_EXECUTION_TARGET_PLAYBOOK: toolkit.playbookPath,
  }), 'cyberops environment')

  ctx.effect(() => () => gateway.close(), 'cyberops masked URL gateway')

  ctx.systemPrompt.section({
    name: 'cyberops:toolkit',
    order: 50,
    text: ({ agent }) => agent && gateway.sessionState(agent.id)?.active
      ? cyberOpsPrompt(toolkit, gateway.sessionState(agent.id)?.directAccess)
      : '',
  })

  ctx.systemPrompt.context({
    name: 'cyberops:targets',
    order: 45,
    text: ({ agent }) => agent ? gateway.context(agent.id) : '',
  })

  ctx.on('agent/pre-step', async ({ agent, turn }, next) => {
    if (corruptedRouteCircuit.beginTurn(agent, turn)) {
      agent.cancel({
        kind: 'hook',
        reason: 'CyberOps stopped a repeated corrupted masked-route loop after three denied attempts. Valid tool calls remain unlimited.',
      })
      return { kind: 'reject' }
    }

    const decision = await next()
    if (decision.kind === 'reject') return decision

    const before = gateway.context(agent.id)
    const messages = await Promise.all(
      decision.messages.map((message) => projectMessage(gateway, agent.id, message)),
    )
    await gateway.flush()
    const after = gateway.context(agent.id)
    const contextChanged = after !== before
    const activated = !before && Boolean(after)
    const activationContext = activated
      ? `${cyberOpsPrompt(toolkit, gateway.sessionState(agent.id)?.directAccess)}\n\n${after}`
      : after
    return {
      kind: 'enter',
      messages: contextChanged && after
        ? [...messages, cyberOpsContextMessage(activationContext)]
        : messages,
    }
  })

  ctx.on('agent/session-start', ({ agent, source }) => {
    if (source === 'clear') gateway.dropSession(agent.id)
  })

  ctx.tools.guard((execution) => {
    if (!execution.agent) return undefined
    const reason = gateway.guardReason(execution.agent.id, execution.name, execution.arguments)
    if (reason?.startsWith(CORRUPTED_ROUTE_REASON_PREFIX)) {
      corruptedRouteCircuit.record(execution.agent)
    } else if (!reason && gateway.hasExactTaskRoute(execution.agent.id, execution.arguments)) {
      corruptedRouteCircuit.clear(execution.agent)
    }
    return reason
  })

  ctx.on('tools/post-execute', async (execution, result, next) => {
    const decision = await next()
    if (decision.kind !== 'accept' || !execution.agent || !gateway.sessionState(execution.agent.id)?.active) {
      return decision
    }
    const additionalContexts = decision.additionalContexts

    if (execution.parent !== undefined && !result.isError) {
      const value = Object.hasOwn(decision, 'value') ? decision.value : result.value
      return {
        kind: 'accept',
        value: gateway.providerValue(execution.agent.id, value),
        ...(additionalContexts ? { additionalContexts } : {}),
      }
    }

    const content = projectContent(
      gateway,
      execution.agent.id,
      decision.content ?? result.content,
    )
    return {
      kind: 'accept',
      content,
      ...(additionalContexts ? { additionalContexts } : {}),
    }
  })

  ctx.on('tools/code-dispatch-log', async (dispatch, next) => {
    const content = await next()
    if (!dispatch.agent || !gateway.sessionState(dispatch.agent.id)?.active) return content
    return projectContent(gateway, dispatch.agent.id, content)
  })

  // The composer toggle drives this command; `/cyber-mode` is also usable by
  // hand. Arming only flips the session's prompt state — no target is
  // authorized, so `/cyber-2 <URL>` (or a referenced URL) is still required
  // before any masked route exists.
  ctx.inject(['commands'], (commandCtx) => {
    commandCtx.commands.register({
      name: CYBER_MODE_COMMAND,
      description: 'Arm or disarm CyberOps red-team mode for this session',
      input: { hint: '[on|off|status]' },
      handler: ({ agent, rawInput }) => {
        const mode = rawInput.trim().toLowerCase()
        const direct = config.armDirectAccess !== false
        if (mode === 'on') {
          gateway.setArmed(agent.id, true, direct)
          return {
            kind: 'success',
            text: cyberModeText('on', { direct, tools: toolkit.tools.length }),
          }
        }
        if (mode === 'off') {
          gateway.setArmed(agent.id, false)
          return { kind: 'success', text: cyberModeText('off') }
        }
        if (mode === '' || mode === 'status') {
          const state = gateway.sessionState(agent.id)
          return {
            kind: 'success',
            text: cyberModeText(state?.active ? 'on' : 'off', {
              direct: state?.directAccess,
              tools: toolkit.tools.length,
            }),
          }
        }
        return { kind: 'error', text: 'Usage: /cyber-mode [on|off|status]' }
      },
    })
  })

  ctx.logger?.('cyberops').info(
    'verified CyberOps toolkit %s with %d tools; one masked listener per route; state %s',
    toolkit.bundleVersion,
    toolkit.tools.length,
    statePath,
  )
}

export { CyberOpsGateway } from './siteproxy.js'
