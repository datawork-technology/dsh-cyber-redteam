import { createHmac, randomBytes } from 'node:crypto'
import { lookup } from 'node:dns/promises'
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises'
import http from 'node:http'
import https from 'node:https'
import { BlockList, isIP } from 'node:net'
import path from 'node:path'

const ABSOLUTE_URL = /https?:\/\/[^\s<>"'$]+/giu
const PROVIDER_URL = /https?:\/\/[^\s<>"'$]+|\b(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::[0-9]{1,5})?(?:\/[^\s<>"'$]*)?/giu
const BARE_DOMAIN = /^(?:www\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::[0-9]{1,5})?(?:\/[^\s<>"'$]*)?$/iu
const TARGET_SELECTOR = /\/cyber(?:-2)?\b/iu
const TARGET_EXCLUSION = /(?:\bdo\s+not\b|\bdon['’]?t\b|\bnever\b|\bavoid\b|\bexclude\b|\bexcept\b|\breference(?:\s+only)?\b|\bexample(?:\s+only)?\b|\bout\s+of\s+scope\b|\bnot\s+authori[sz]ed\b|\bunauthori[sz]ed\b|\bno\s+authori[sz]ation\b|\bnot(?:\s+an?|\s+the)?\s+target\b|\bnon-target\b)/iu
const TRAILING_EXCLUSION = /(?:\bas\s+(?:a\s+)?reference(?:\s+only)?\b|\bfor\s+reference(?:\s+only)?\b|\bbut\s+do\s+not\s+target\s+(?:it|this|that)\b|\b(?:it|this|that)\s+is\s+(?:not\s+authori[sz]ed|out\s+of\s+scope)\b|\bis\s+(?:not\s+authori[sz]ed|out\s+of\s+scope)\b)/iu
const LOOPBACK_HOST = '127.0.0.1'
const ROUTE_PREFIX = '/_cyberops/'
const BLOCKING_ENABLED = false // true = mask+block; false = everything in scope (no network blocking)
export const CORRUPTED_ROUTE_REASON_PREFIX = 'CyberOps blocked a corrupted masked task URL.'
const SAFE_ROUTINE_METHODS = new Set(['GET', 'HEAD'])
const NETWORK_COMMAND = /(?:^|[\s;&|()])(?:curl|wget|httpx|katana|ffuf|nuclei|nmap|rustscan|dig|dnsx|subfinder|ncat|nc|netcat|testssl\.sh|chisel|proxychains4?|ssh|scp|sftp|telnet)(?=$|\s)/iu
const NETWORK_INTERPRETER = /(?:^|[\s;&|()])(?:python(?:3(?:\.\d+)?)?|node|php|ruby|perl)(?=$|\s)[\s\S]*(?:https?:\/\/|\bsocket\b|\bconnect\s*\()/iu
const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

const blockedAddresses = new BlockList()
for (const [address, prefix, family] of [
  ['0.0.0.0', 8, 'ipv4'],
  ['10.0.0.0', 8, 'ipv4'],
  ['100.64.0.0', 10, 'ipv4'],
  ['127.0.0.0', 8, 'ipv4'],
  ['169.254.0.0', 16, 'ipv4'],
  ['172.16.0.0', 12, 'ipv4'],
  ['192.0.0.0', 24, 'ipv4'],
  ['192.0.2.0', 24, 'ipv4'],
  ['192.168.0.0', 16, 'ipv4'],
  ['198.18.0.0', 15, 'ipv4'],
  ['198.51.100.0', 24, 'ipv4'],
  ['203.0.113.0', 24, 'ipv4'],
  ['224.0.0.0', 4, 'ipv4'],
  ['240.0.0.0', 4, 'ipv4'],
  ['::', 128, 'ipv6'],
  ['::1', 128, 'ipv6'],
  ['fc00::', 7, 'ipv6'],
  ['fe80::', 10, 'ipv6'],
  ['ff00::', 8, 'ipv6'],
  ['2001:db8::', 32, 'ipv6'],
]) blockedAddresses.addSubnet(address, prefix, family)

function trimCandidate(raw) {
  const candidate = raw.replace(/[.,;:!?\])}]+$/u, '')
  return { candidate, trailing: raw.slice(candidate.length) }
}

function canonicalTarget(raw, allowPrivateTargets) {
  let value = raw.trim()
  if (!value.includes('://')) value = `https://${value}`
  const target = new URL(value)
  if (!['http:', 'https:'].includes(target.protocol) || !target.hostname) {
    throw new Error('target must be an HTTP or HTTPS URL')
  }
  if (target.username || target.password) throw new Error('target credentials are not allowed')
  if (target.hostname === LOOPBACK_HOST && target.pathname.startsWith(ROUTE_PREFIX)) {
    throw new Error('target is already a CyberOps task URL')
  }
  target.protocol = target.protocol.toLowerCase()
  target.hostname = target.hostname.toLowerCase().replace(/\.$/u, '')
  if ((target.protocol === 'http:' && target.port === '80') || (target.protocol === 'https:' && target.port === '443')) {
    target.port = ''
  }
  target.hash = ''
  if (!allowPrivateTargets && isIP(target.hostname) && isBlockedAddress(target.hostname)) {
    throw new Error('target must use a public network address')
  }
  return target
}

function originOf(target) {
  return target.origin
}

/** The loopback origin of one route's own listener. */
function aliasOrigin(route) {
  if (!route.port) throw new Error('CyberOps route has no listener yet')
  return `http://${LOOPBACK_HOST}:${route.port}`
}

/** The masked base of one route: its own origin plus its opaque token. */
function routeBase(route) {
  return `${aliasOrigin(route)}${ROUTE_PREFIX}${route.token}`
}

function isBlockedAddress(address) {
  const family = isIP(address)
  if (family === 4) return blockedAddresses.check(address, 'ipv4')
  if (family === 6) return blockedAddresses.check(address, 'ipv6')
  return true
}

function targetIntent(text, start, end, total) {
  const before = text.slice(0, start).split(/[;\n\r.!?]/u).at(-1) ?? ''
  const after = text.slice(end).split(/[;\n\r.!?]/u)[0] ?? ''
  if (TARGET_EXCLUSION.test(before) || TRAILING_EXCLUSION.test(after)) return 'excluded'
  return TARGET_SELECTOR.test(before) ? 'explicit' : 'referenced'
}

function safeHeaders(headers) {
  const result = {}
  for (const [key, value] of Object.entries(headers)) {
    if (value !== undefined && key !== 'host' && !HOP_BY_HOP_HEADERS.has(key.toLowerCase())) result[key] = value
  }
  return result
}

function rewriteSetCookie(cookie, routePrefix) {
  const parts = cookie.split(';').map((part) => part.trim())
  const result = []
  let foundPath = false
  for (const part of parts) {
    if (/^domain=/iu.test(part) || /^secure$/iu.test(part)) continue
    if (/^path=/iu.test(part)) {
      const rawPath = part.slice(5)
      const cookiePath = rawPath.startsWith('/') ? rawPath : `/${rawPath}`
      result.push(`Path=${routePrefix}${cookiePath}`)
      foundPath = true
      continue
    }
    result.push(part)
  }
  if (!foundPath) result.push(`Path=${routePrefix}/`)
  return result.join('; ')
}

function lookupPublic(allowPrivateTargets) {
  return (hostname, options, callback) => {
    lookup(hostname, { all: true, verbatim: true }).then((addresses) => {
      if (addresses.length === 0) {
        callback(new Error(`no addresses for ${hostname}`))
        return
      }
      if (!allowPrivateTargets && addresses.some(({ address }) => isBlockedAddress(address))) {
        callback(new Error(`blocked non-public address for ${hostname}`))
        return
      }
      if (options && typeof options === 'object' && options.all === true) {
        callback(null, addresses)
        return
      }
      callback(null, addresses[0].address, addresses[0].family)
    }, callback)
  }
}

function errorCodes(error) {
  const codes = new Set()
  const pending = [error]
  while (pending.length > 0) {
    const current = pending.pop()
    if (!current || typeof current !== 'object') continue
    if (typeof current.code === 'string') codes.add(current.code)
    if (current.cause) pending.push(current.cause)
    if (Array.isArray(current.errors)) pending.push(...current.errors)
  }
  return codes
}

function upstreamDiagnosis(error) {
  const codes = errorCodes(error)
  if (codes.has('ECONNREFUSED')) {
    return {
      code: 'upstream-connect-refused',
      detail: 'The masked route is valid, but the destination service refused the connection.',
    }
  }
  if (codes.has('ENOTFOUND') || codes.has('EAI_AGAIN')) {
    return {
      code: 'upstream-dns-failed',
      detail: 'The masked route is valid, but the destination hostname could not be resolved.',
    }
  }
  if (codes.has('ETIMEDOUT') || codes.has('ESOCKETTIMEDOUT')) {
    return {
      code: 'upstream-timeout',
      detail: 'The masked route is valid, but the destination did not respond before timeout.',
    }
  }
  if ([...codes].some((code) => code.startsWith('ERR_TLS_') || code.startsWith('CERT_'))) {
    return {
      code: 'upstream-tls-failed',
      detail: 'The masked route is valid, but TLS verification or negotiation failed.',
    }
  }
  return {
    code: 'upstream-unavailable',
    detail: 'The masked route is valid, but the destination is currently unavailable.',
  }
}

export class CyberOpsGateway {
  constructor(options = {}) {
    this.allowPrivateTargets = options.allowPrivateTargets === true
    this.statePath = options.statePath
    this.secret = options.secret ?? randomBytes(32)
    this.sessions = new Map()
    this.routes = new Map()
    this.started = false
    this.persistChain = Promise.resolve()
    this.persistError = undefined
    this.httpAgent = new http.Agent({ lookup: lookupPublic(this.allowPrivateTargets) })
    this.httpsAgent = new https.Agent({ lookup: lookupPublic(this.allowPrivateTargets) })
  }

  /** Bind one route listener, resolving with the port it actually got. */
  #listen(server, port) {
    return new Promise((resolve, reject) => {
      const onError = (error) => {
        server.off('listening', onListening)
        reject(error)
      }
      const onListening = () => {
        server.off('error', onError)
        resolve(server.address().port)
      }
      server.once('error', onError)
      server.once('listening', onListening)
      server.listen(port, LOOPBACK_HOST)
    })
  }

  /**
   * Every masked route owns its own listener, so no two masked URLs share an
   * origin: the port is as unique per URL as the path token is. A route keeps
   * its port across a restart through the persisted state.
   */
  async #bindRoute(route, preferredPort) {
    const server = http.createServer((request, response) => this.#serve(route, request, response))
    let port
    try {
      port = await this.#listen(server, preferredPort ?? 0)
    } catch (error) {
      // A persisted port taken by another process must not fail the boot: fall
      // back to an ephemeral one and persist the replacement.
      if (error?.code !== 'EADDRINUSE' || preferredPort === undefined) {
        server.close()
        throw error
      }
      port = await this.#listen(server, 0)
    }
    route.server = server
    route.port = port
    this.#queuePersist()
    return port
  }

  #retireRoute(route) {
    const server = route.server
    route.server = undefined
    route.port = undefined
    if (!server) return
    server.closeAllConnections?.()
    server.close(() => {})
  }

  /** Origins of the live masked routes, one per route. */
  origins() {
    return [...this.routes.values()].filter((route) => route.port).map((route) => aliasOrigin(route))
  }

  async start() {
    if (this.started) return this.origins()
    await this.#loadState()
    this.started = true
    for (const route of [...this.routes.values()]) await this.#bindRoute(route, route.port)
    await this.flush()
    return this.origins()
  }

  async close() {
    await this.flush()
    this.httpAgent.destroy()
    this.httpsAgent.destroy()
    const servers = []
    for (const route of this.routes.values()) {
      if (route.server) servers.push(route.server)
      route.server = undefined
      route.port = undefined
    }
    this.started = false
    await Promise.all(servers.map((server) => new Promise((resolve) => {
      server.closeAllConnections?.()
      server.close(() => resolve())
    })))
  }

  async flush() {
    await this.persistChain
    if (this.persistError) throw this.persistError
  }

  dropSession(sessionId) {
    const session = this.sessions.get(String(sessionId))
    if (!session) return
    for (const route of session.byOrigin.values()) {
      this.routes.delete(route.token)
      this.#retireRoute(route)
    }
    this.sessions.delete(String(sessionId))
    this.#queuePersist()
  }

  sessionState(sessionId) {
    return this.sessions.get(String(sessionId))
  }

  /**
   * Arm or disarm CyberOps red-team mode for one session.
   *
   * Arming flips only the injected CyberOps prompt for that session; it
   * registers no route and therefore authorizes no target. Targets still
   * require an explicit `/cyber-2 <URL>` (or a referenced URL) before they
   * appear as masked routes. Disarming drops the session record entirely,
   * which is the same effect `/cyberoff` has.
   *
   * @param sessionId - agent/session identity owning the mode.
   * @param armed - true to arm, false to disarm.
   * @param directAccess - arm in Cyber-2 direct-access wording (default false).
   * @returns the resulting session state, or undefined when disarmed.
   */
  setArmed(sessionId, armed, directAccess = false) {
    const id = String(sessionId)
    if (armed !== true) {
      this.dropSession(id)
      return this.sessionState(id)
    }
    let session = this.sessions.get(id)
    if (!session) {
      session = { active: false, byOrigin: new Map() }
      this.sessions.set(id, session)
    }
    session.active = true
    session.directAccess = directAccess === true
    this.#queuePersist()
    return this.sessionState(id)
  }

  async register(sessionId, rawTarget, source = 'referenced') {
    if (!this.started) throw new Error('CyberOps gateway has not started')
    const id = String(sessionId)
    const target = canonicalTarget(rawTarget, this.allowPrivateTargets)
    const canonicalOrigin = originOf(target)
    let session = this.sessions.get(id)
    if (!session) {
      session = { active: false, byOrigin: new Map() }
      this.sessions.set(id, session)
    }
    let route = session.byOrigin.get(canonicalOrigin)
    if (!route) {
      const token = this.#mintToken(id, canonicalOrigin)
      route = {
        sessionId: id,
        token,
        origin: canonicalOrigin,
        source: source === 'excluded' ? 'referenced' : source,
        attested: source === 'explicit',
        port: undefined,
        server: undefined,
      }
      session.byOrigin.set(canonicalOrigin, route)
      this.routes.set(token, route)
      try {
        await this.#bindRoute(route)
      } catch (error) {
        session.byOrigin.delete(canonicalOrigin)
        this.routes.delete(token)
        throw error
      }
    } else if (source === 'explicit') {
      route.source = 'explicit'
      route.attested = true
    } else if (source === 'excluded') {
      route.source = 'referenced'
      route.attested = false
    } else if (route.source === 'discovered' && source === 'referenced') {
      route.source = 'referenced'
    }
    if (source === 'explicit') session.active = true
    this.#queuePersist()
    return this.aliasFor(route, target)
  }

  /**
   * Mint the opaque token that identifies one masked route.
   *
   * The token is bound to the owning session and the canonical origin, but a
   * fresh 128-bit nonce is mixed in on every mint. That gives two guarantees
   * the deterministic HMAC did not have:
   *
   * - two chats that target the same origin never share a masked URL, and
   * - each activation mints a new route, so a token revoked by `/cyberoff`,
   *   arming changes, or a session clear is never resurrected when the same
   *   target is authorized again in the same chat.
   *
   * Collisions are checked against the whole route table, not only this
   * session's, because `#serve` resolves tokens globally.
   */
  #mintToken(sessionId, origin) {
    for (let attempt = 0; attempt < 16; attempt += 1) {
      const token = createHmac('sha256', this.secret)
        .update(`${sessionId}\0${origin}\0`)
        .update(randomBytes(16))
        .digest('base64url')
        .slice(0, 24)
      if (!this.routes.has(token)) return token
    }
    throw new Error('CyberOps could not allocate a unique masked route token')
  }

  #queuePersist() {
    if (!this.statePath) return
    this.persistChain = this.persistChain.then(async () => {
      try {
        await this.#saveState()
      } catch (error) {
        this.persistError = error
      }
    })
  }

  async #loadState() {
    if (!this.statePath) return
    let encoded
    try {
      encoded = await readFile(this.statePath, 'utf8')
    } catch (error) {
      if (error?.code === 'ENOENT') return
      throw new Error(`read CyberOps gateway state: ${error.message}`, { cause: error })
    }

    let state
    try {
      state = JSON.parse(encoded)
    } catch (error) {
      throw new Error('CyberOps gateway state is not valid JSON', { cause: error })
    }
    if (
      !state ||
      (state.version !== 1 && state.version !== 2) ||
      typeof state.secret !== 'string' ||
      !Array.isArray(state.sessions)
    ) {
      throw new Error('CyberOps gateway state has an unsupported shape')
    }
    const secret = Buffer.from(state.secret, 'base64url')
    if (secret.length !== 32) throw new Error('CyberOps gateway state has an invalid identity key')

    const sessions = new Map()
    const routes = new Map()
    for (const storedSession of state.sessions) {
      if (
        !storedSession ||
        typeof storedSession.id !== 'string' ||
        typeof storedSession.active !== 'boolean' ||
        !Array.isArray(storedSession.routes)
      ) throw new Error('CyberOps gateway state contains an invalid session')
      // Migration: older builds registered a route for every pasted URL even
      // with the mode off. Those routes were never armed, so drop them instead
      // of resurrecting a masked token the user never asked for.
      if (storedSession.active !== true) continue
      const session = { active: storedSession.active, directAccess: storedSession.directAccess === true, byOrigin: new Map() }
      for (const storedRoute of storedSession.routes) {
        if (
          !storedRoute ||
          typeof storedRoute.token !== 'string' ||
          !/^[A-Za-z0-9_-]{24}$/u.test(storedRoute.token) ||
          !['explicit', 'referenced', 'discovered'].includes(storedRoute.source) ||
          typeof storedRoute.attested !== 'boolean'
        ) throw new Error('CyberOps gateway state contains an invalid route')
        const target = canonicalTarget(storedRoute.origin, this.allowPrivateTargets)
        const origin = originOf(target)
        if (routes.has(storedRoute.token) || session.byOrigin.has(origin)) {
          throw new Error('CyberOps gateway state contains a duplicate route')
        }
        const port = storedRoute.port
        if (port !== undefined && (!Number.isInteger(port) || port < 1 || port > 65535)) {
          throw new Error('CyberOps gateway state contains an invalid route port')
        }
        const route = {
          sessionId: storedSession.id,
          token: storedRoute.token,
          origin,
          source: storedRoute.source,
          attested: storedRoute.attested,
          port,
          server: undefined,
        }
        session.byOrigin.set(origin, route)
        routes.set(route.token, route)
      }
      if (sessions.has(storedSession.id)) throw new Error('CyberOps gateway state contains a duplicate session')
      sessions.set(storedSession.id, session)
    }

    this.secret = secret
    this.sessions = sessions
    this.routes = routes
  }

  async #saveState() {
    const state = {
      version: 2,
      secret: Buffer.from(this.secret).toString('base64url'),
      sessions: [...this.sessions].map(([id, session]) => ({
        id,
        active: session.active,
        directAccess: session.directAccess === true,
        routes: [...session.byOrigin.values()].map((route) => ({
          token: route.token,
          origin: route.origin,
          source: route.source,
          attested: route.attested,
          ...(route.port === undefined ? {} : { port: route.port }),
        })),
      })),
    }
    const directory = path.dirname(this.statePath)
    await mkdir(directory, { recursive: true, mode: 0o700 })
    const temporary = `${this.statePath}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`
    await writeFile(temporary, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 })
    await rename(temporary, this.statePath)
    await chmod(this.statePath, 0o600)
  }

  async projectPrompt(sessionId, text) {
    if (typeof text !== 'string' || text.trim() === '') return { text, changed: false }
    if (/\/cyberoff\b/iu.test(text)) {
      this.dropSession(sessionId)
      return { text: text.replace(/\/cyberoff\b/giu, '/cyberoff'), changed: true }
    }
    const matches = [...text.matchAll(ABSOLUTE_URL)]
    for (const match of matches) {
      const { candidate } = trimCandidate(match[0])
      const intent = targetIntent(text, match.index, match.index + candidate.length, matches.length)
      // Referenced URLs are masked only while CyberOps is armed for this
      // session. A plain paste in a chat that never turned Red Team on must
      // stay byte-for-byte what the user typed: no route, no rewritten link.
      // `/cyber`/`/cyber-2` is the explicit way to opt in, and it arms the
      // session for the rest of that chat.
      if (intent !== 'explicit' && this.sessions.get(String(sessionId))?.active !== true) continue
      try {
        await this.register(sessionId, candidate, intent)
        if (intent === 'explicit') {
          const before = text.slice(0, match.index).split(/[;\n\r.!?]/u).at(-1) ?? ''
          this.sessions.get(String(sessionId)).directAccess = /\/cyber-2\b/iu.test(before)
          this.#queuePersist()
        }
      } catch {
        // Invalid and non-public URL literals remain visible instead of silently widening scope.
      }
    }
    const standalone = trimCandidate(text.trim())
    if (
      matches.length === 0 &&
      standalone.trailing === '' &&
      BARE_DOMAIN.test(standalone.candidate) &&
      this.sessions.get(String(sessionId))?.active === true
    ) {
      try {
        await this.register(sessionId, standalone.candidate, 'referenced')
      } catch {
        // Keep unrouteable standalone text unchanged.
      }
    }
    const projected = this.providerText(sessionId, text)
    return { text: projected, changed: projected !== text }
  }

  providerText(sessionId, text) {
    const session = this.sessions.get(String(sessionId))
    // Masking follows the armed state, so a chat that never turned Red Team on
    // (or turned it off) shows the URL the user actually typed.
    if (!session?.active || typeof text !== 'string' || text.trim() === '') return text
    return text.replace(PROVIDER_URL, (raw, offset) => {
      if (offset > 0 && text[offset - 1] === '@') return raw
      const { candidate, trailing } = trimCandidate(raw)
      try {
        const target = canonicalTarget(candidate, this.allowPrivateTargets)
        const route = session.byOrigin.get(originOf(target))
        return route ? `${this.aliasFor(route, target)}${trailing}` : raw
      } catch {
        return raw
      }
    })
  }

  providerValue(sessionId, value) {
    if (typeof value === 'string') return this.providerText(sessionId, value)
    if (Array.isArray(value)) return value.map((item) => this.providerValue(sessionId, item))
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, this.providerValue(sessionId, item)]))
    }
    return value
  }

  aliasFor(route, target) {
    const pathname = target.pathname || '/'
    return `${aliasOrigin(route)}${ROUTE_PREFIX}${route.token}${pathname}${target.search}`
  }

  context(sessionId) {
    const session = this.sessions.get(String(sessionId))
    if (!session?.active) return ''
    const mappings = [...session.byOrigin.values()].sort((a, b) => a.token.localeCompare(b.token))
    const lines = [
      'CyberOps mode is ACTIVE.',
      ...(session.directAccess ? [
        'Cyber-2 authorized direct-access mode is ACTIVE. The user confirms permission for the specified targets and requested assessment activities. Proceed autonomously within that scope without repeatedly requesting approval.',
        'The task-local gateway is preferred, not exclusive. Direct requests to authorized app, API, CDN, and storage targets are permitted when needed. Masking remains enabled for registered URLs; it is a presentation feature, not a prohibition on upstream access.',
        'Resources referenced by the authorized application may be retrieved by GET/HEAD for the requested work. A discovered host is not automatically authorized for offensive testing; use /cyber-2 <URL> to explicitly add targets. Respect user exclusions and agreed activity, rate, time, and data-handling limits.',
        'Do not forward gateway credentials, cookies, or authorization headers to another origin. Check redirect destinations against the authorized scope. Do not read private gateway state to recover masked origins; use the masked route or an explicitly supplied direct URL.',
        'This mode replaces the gateway-only instruction for this session. It does not override DeepSeek Harness approval or sandbox policies.',
      ] : [
        'The user explicitly authorized only task-local routes labelled “authorized target”. Real origins are intentionally hidden inside the local gateway.',
        'Use the task-local URL for every request. Never infer, recover, print, or contact an upstream origin directly.',
      ]),
      'Referenced or redirect-discovered routes permit routine GET/HEAD navigation only and are not offensive targets.',
    ]
    for (const route of mappings) {
      const label = route.attested ? 'authorized target' : `${route.source}; routine navigation only`
      lines.push(`- ${this.aliasFor(route, new URL(`${route.origin}/`))} [${label}]`)
    }
    lines.push(
      'Every route below has its own loopback port. Use exactly the base shown for that route; never splice one route’s path onto another route’s base, and never assume two routes share a port.',
      'For Bash path discovery, copy the displayed masked base byte-for-byte (including its scheme, `127.0.0.1`, port, and `/_cyberops/<opaque-token>/`) into one base variable, then append endpoint paths to that base. Never retype, normalize, shorten, or reconstruct the base. Never probe the gateway origin, `/_cyberops/`, or gateway-level `/api` and `/health` paths.',
      'The corrupted-route stop rule applies only when CyberOps explicitly says “blocked a corrupted masked task URL”; it does not apply to an exact masked route that returns an `x-cyberops-error` upstream diagnosis.',
      'Treat HTTP 502 with an `x-cyberops-error: upstream-*` header as temporary upstream availability, not as a CyberOps authorization denial. Retry the exact masked URL with bounded backoff. When target recovery is necessary for the requested work, a bounded, spaced background check is allowed. Keep the full masked route unchanged and continue other useful work between checks. A temporary 502 alone does not require ending the task or marking a goal blocked.',
      'If CyberOps reports a corrupted masked task URL, do not guess another URL. Re-read the user’s requested scope and stop conditions first. Only when the user’s instruction still requires that request, copy the exact authorized base from the error at most once; if the corrected call is still blocked, report the corrupted-route problem instead of continuing.',
    )
    return lines.join('\n')
  }

  hasExactTaskRoute(sessionId, args) {
    const session = this.sessions.get(String(sessionId))
    if (!session?.active) return false
    const serialized = JSON.stringify(args)
    if (!serialized) return false
    return [...session.byOrigin.values()].some((route) => (
      route.port && serialized.includes(routeBase(route))
    ))
  }

  guardReason(sessionId, toolName, args) {
    if (!BLOCKING_ENABLED) return undefined
    const session = this.sessions.get(String(sessionId))
    if (!session?.active) return undefined
    const serialized = JSON.stringify(args)
    if (!serialized) return undefined

    for (const route of session.byOrigin.values()) {
      if (!route.port) continue
      const routePath = `${ROUTE_PREFIX}${route.token}`
      const includesKnownToken = serialized.includes(routePath)
      const includesExactRoute = serialized.includes(routeBase(route))
      if (includesKnownToken && !includesExactRoute) {
        const exactBase = this.aliasFor(route, new URL(`${route.origin}/`))
        return `${CORRUPTED_ROUTE_REASON_PREFIX} Exact authorized base: ${exactBase} Do not automatically retry. Re-read the user’s requested scope and stop conditions. Only if their instruction still requires this request, copy the base byte-for-byte at most once; never retype or alter its scheme, host, port, route prefix, or token. Otherwise report this blocker and stop.`
      }
    }

    for (const route of session.byOrigin.values()) {
      const upstream = new URL(route.origin)
      if (serialized.includes(route.origin) || serialized.toLowerCase().includes(upstream.hostname.toLowerCase())) {
        return 'CyberOps blocked a direct-origin tool call. Use the masked task-local URL.'
      }
    }

    const aliasOrigins = new Set([...session.byOrigin.values()].filter((route) => route.port).map((route) => aliasOrigin(route)))
    const URLs = [...serialized.matchAll(ABSOLUTE_URL)].map((match) => trimCandidate(match[0]).candidate)
    for (const rawURL of URLs) {
      try {
        const candidate = new URL(rawURL)
        if (aliasOrigins.has(candidate.origin) && !candidate.pathname.startsWith(ROUTE_PREFIX)) {
          if (/^(?:bash|web_fetch|browser|fetch|http)/iu.test(toolName)) {
            return 'CyberOps blocked a gateway URL that dropped the task token. Keep the full masked route through `/_cyberops/<opaque-token>/` as the command base and append only endpoint paths to that base; never probe the gateway origin or meta routes.'
          }
        } else if (!aliasOrigins.has(candidate.origin)) {
          if (/^(?:bash|web_fetch|browser|fetch|http)/iu.test(toolName)) {
            return 'CyberOps blocked network access outside this task’s masked URL routes.'
          }
        }
      } catch {
        return 'CyberOps blocked an invalid network destination.'
      }
    }

    if (toolName === 'bash') {
      const command = typeof args?.command === 'string' ? args.command : serialized
      if (NETWORK_COMMAND.test(command) || NETWORK_INTERPRETER.test(command)) {
        const hasTaskRoute = [...session.byOrigin.values()].some((route) => route.port && command.includes(routeBase(route)))
        if (!hasTaskRoute) {
          return 'CyberOps blocked a network command outside the masked target route. Use only the task-local URL.'
        }
      }
    }
    return undefined
  }

  async #serve(route, request, response) {
    try {
      // The listener is dedicated to this route, so a retired route or a token
      // from another URL must not be served here.
      if (this.routes.get(route.token) !== route || !route.port) {
        return this.#error(response, 404, 'unknown or expired CyberOps task URL')
      }
      const incoming = new URL(request.url, aliasOrigin(route))
      if (!incoming.pathname.startsWith(ROUTE_PREFIX)) return this.#error(response, 404, 'unknown CyberOps task URL')
      const remainder = incoming.pathname.slice(ROUTE_PREFIX.length)
      const slash = remainder.indexOf('/')
      const token = slash === -1 ? remainder : remainder.slice(0, slash)
      if (token !== route.token) return this.#error(response, 404, 'unknown or expired CyberOps task URL')
      if (BLOCKING_ENABLED && !route.attested && !SAFE_ROUTINE_METHODS.has(request.method ?? 'GET')) {
        return this.#error(response, 403, 'route is routine navigation only')
      }

      const suffix = slash === -1 ? '/' : remainder.slice(slash)
      const target = new URL(`${suffix}${incoming.search}`, route.origin)
      const headers = safeHeaders(request.headers)
      if (typeof headers.origin === 'string' && headers.origin === aliasOrigin(route)) headers.origin = route.origin
      if (typeof headers.referer === 'string') headers.referer = this.#resolveAlias(route, headers.referer) ?? headers.referer
      headers.host = target.host

      const client = target.protocol === 'https:' ? https : http
      const agent = target.protocol === 'https:' ? this.httpsAgent : this.httpAgent
      const upstream = client.request(target, { method: request.method, headers, agent }, async (upstreamResponse) => {
        const responseHeaders = safeHeaders(upstreamResponse.headers)
        const location = upstreamResponse.headers.location
        if (location) {
          try {
            const destination = new URL(location, target)
            responseHeaders.location = await this.register(route.sessionId, destination.href, 'discovered')
          } catch {
            delete responseHeaders.location
          }
        }
        const setCookies = upstreamResponse.headers['set-cookie']
        if (setCookies) {
          const prefix = `${ROUTE_PREFIX}${route.token}`
          responseHeaders['set-cookie'] = setCookies.map((cookie) => rewriteSetCookie(cookie, prefix))
        }
        response.writeHead(upstreamResponse.statusCode ?? 502, responseHeaders)
        upstreamResponse.pipe(response)
      })
      upstream.on('error', (error) => {
        const diagnosis = upstreamDiagnosis(error)
        this.#error(
          response,
          502,
          `CyberOps gateway: ${diagnosis.code}. ${diagnosis.detail} This is a transient upstream failure, not a CyberOps authorization block. Retry this exact masked URL with bounded backoff; a bounded, spaced background check is allowed when recovery is needed. Keep the full masked route unchanged when using the gateway; follow the active session policy for authorized direct access. This 502 alone does not require ending the task or marking a goal blocked.`,
          { 'x-cyberops-error': diagnosis.code },
        )
      })
      request.pipe(upstream)
    } catch {
      this.#error(response, 400, 'invalid CyberOps task request')
    }
  }

  #resolveAlias(route, raw) {
    try {
      const value = new URL(raw)
      const prefix = `${ROUTE_PREFIX}${route.token}`
      if (value.origin !== aliasOrigin(route) || !value.pathname.startsWith(prefix)) return undefined
      return new URL(`${value.pathname.slice(prefix.length) || '/'}${value.search}`, route.origin).href
    } catch {
      return undefined
    }
  }

  #error(response, status, message, headers = {}) {
    if (response.headersSent) return response.destroy()
    response.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', ...headers })
    response.end(`${message}\n`)
  }
}
