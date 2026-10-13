import { createServer as createHttpServer, type Server } from 'node:http';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createServer } from './server.js';
import { runWithCredentials } from './client.js';
import { logger } from './utils/logger.js';
import { verifyS2sHeader, S2S_HEADER } from './s2s-verify.js';

/**
 * HTTP startup fails closed (CWE-306).
 *
 * An empty CONDUIT_S2S_SECRET used to skip X-Gateway-S2S and let /mcp run.
 * Startup now refuses to listen unless the secret is a real value.
 * Known placeholders are rejected even when MCP_ALLOW_INSECURE_DEV=1, so a
 * copied example cannot sign requests. That flag is the only bypass for an
 * empty secret: it logs a warning and listens on 127.0.0.1 only. A
 * configured secret keeps honoring MCP_HTTP_HOST. The secret is never logged.
 */
const LOOPBACK_HOST = '127.0.0.1';

/** Public example values. A copied placeholder must not verify as a real secret. */
const KNOWN_PLACEHOLDER_SECRETS = new Set([
  'replace-with-a-real-secret',
  'your-s2s-secret',
  'your-secret',
  'changeme',
  'change-me',
  'placeholder',
  'secret',
  'example',
  'replace-me',
  's2s-secret',
]);

const MISSING_S2S_SECRET_ERROR =
  'Refusing to start HTTP server: CONDUIT_S2S_SECRET is empty. ' +
  'An empty secret would accept unauthenticated /mcp requests (CWE-306). ' +
  'Set CONDUIT_S2S_SECRET to the gateway-provisioned service-to-service secret, ' +
  'or set MCP_ALLOW_INSECURE_DEV=1 to bypass this check for local development only.';

const PLACEHOLDER_S2S_SECRET_ERROR =
  'Refusing to start HTTP server: CONDUIT_S2S_SECRET is a known placeholder. ' +
  'Generate a secret with `openssl rand -hex 32` and set CONDUIT_S2S_SECRET to that value. ' +
  'A placeholder cannot verify as a real X-Gateway-S2S secret.';

const INSECURE_DEV_WARNING =
  'WARNING: MCP_ALLOW_INSECURE_DEV=1 is set and CONDUIT_S2S_SECRET is empty. ' +
  'The HTTP server is starting WITHOUT service-to-service authentication and listens on 127.0.0.1 only. ' +
  'Do not use MCP_ALLOW_INSECURE_DEV outside local development.';

const S2S_UNAUTHORIZED = {
  error: 'Missing or invalid X-Gateway-S2S header: this endpoint only accepts requests signed by the gateway.',
};

const GATEWAY_CREDENTIALS_UNAUTHORIZED = {
  error: 'Missing credentials',
  message: 'Gateway mode requires the X-DNSFilter-Api-Key header',
  required: ['X-DNSFilter-Api-Key'],
};

function headerValue(value: string | string[] | undefined): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function readS2sSecret(): { secret: string; placeholder: boolean } {
  const raw = (process.env.CONDUIT_S2S_SECRET ?? '').trim();
  if (raw && KNOWN_PLACEHOLDER_SECRETS.has(raw.toLowerCase())) {
    return { secret: '', placeholder: true };
  }
  return { secret: raw, placeholder: false };
}

/**
 * No real secret: always 127.0.0.1, including when MCP_HTTP_HOST is 0.0.0.0.
 * A configured secret honors MCP_HTTP_HOST and defaults to loopback when unset.
 */
function resolveBindHost(hasSecret: boolean): string {
  const configured = (process.env.MCP_HTTP_HOST ?? '').trim();
  if (hasSecret) return configured || LOOPBACK_HOST;
  if (configured && configured !== LOOPBACK_HOST) {
    logger.error(
      `WARNING: MCP_HTTP_HOST=${configured} is not ${LOOPBACK_HOST}. ` +
        'MCP_ALLOW_INSECURE_DEV=1 without CONDUIT_S2S_SECRET cannot listen there. ' +
        `Binding ${LOOPBACK_HOST} only.`
    );
  }
  return LOOPBACK_HOST;
}

/**
 * Fail closed before listen. Returns the secret to enforce, or '' when the
 * insecure-dev bypass is active. Never includes the secret in a log line.
 */
function resolveS2sSecretOrExit(): string {
  const { secret, placeholder } = readS2sSecret();
  if (placeholder) {
    logger.error(PLACEHOLDER_S2S_SECRET_ERROR);
    process.exit(1);
  }
  if (secret) return secret;
  if (process.env.MCP_ALLOW_INSECURE_DEV === '1') {
    // error level so LOG_LEVEL=warn|error cannot hide the bypass.
    logger.error(INSECURE_DEV_WARNING);
    return '';
  }
  logger.error(MISSING_S2S_SECRET_ERROR);
  process.exit(1);
}

export async function startHttpServer(): Promise<Server> {
  const s2sSecret = resolveS2sSecretOrExit();
  const port = parseInt(process.env.MCP_HTTP_PORT || '8080', 10);
  const host = resolveBindHost(s2sSecret.length > 0);
  const isGatewayMode = process.env.AUTH_MODE === 'gateway';

  const httpServer = createHttpServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

    // /health is container LIVENESS, not credential-readiness. In gateway
    // mode, credentials arrive per-request via X-DNSFilter-Api-Key, not at
    // startup. This route stays unauthenticated and must not read credentials.
    if (url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          status: 'ok',
          transport: 'http',
          mode: isGatewayMode ? 'gateway' : 'standalone',
          timestamp: new Date().toISOString(),
        })
      );
      return;
    }

    if (url.pathname !== '/mcp') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Not found', endpoints: ['/mcp', '/health'] }));
      return;
    }

    // Empty s2sSecret is only reachable when MCP_ALLOW_INSECURE_DEV=1.
    // A configured secret is always enforced, before credential extraction.
    if (s2sSecret && !verifyS2sHeader(headerValue(req.headers[S2S_HEADER]), s2sSecret)) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(S2S_UNAUTHORIZED));
      return;
    }

    const handle = async () => {
      // SECURITY-CRITICAL invariant: this transport MUST stay stateless
      // (sessionIdGenerator: undefined + enableJsonResponse: true).
      // Per-request tenant credentials are carried in an AsyncLocalStorage
      // context opened by runWithCredentials() below. A stateless
      // request->single-response flow keeps the tool call inside that
      // context - switching to a stateful/SSE transport would let a
      // long-lived connection serve later messages under a stale/foreign
      // credential context.
      const server = createServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: undefined,
        enableJsonResponse: true,
      });
      res.on('close', () => {
        transport.close();
        server.close();
      });
      await server.connect(transport);
      await transport.handleRequest(req, res);
    };

    if (isGatewayMode) {
      // Gateway mode: the API key must arrive on every request. Falling
      // through would resolve DNSFILTER_API_KEY from the process environment,
      // which is not request-scoped.
      const apiKey = headerValue(req.headers['x-dnsfilter-api-key']);
      if (!apiKey) {
        res.writeHead(401, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(GATEWAY_CREDENTIALS_UNAUTHORIZED));
        return;
      }
      await runWithCredentials({ apiKey }, handle);
      return;
    }

    await handle();
  });

  await new Promise<void>((resolve) => {
    httpServer.listen(port, host, () => {
      logger.info(`HTTP streaming server listening on ${host}:${port}`);
      resolve();
    });
  });

  return httpServer;
}

// Vitest imports this module to call startHttpServer. Skip the CLI
// entrypoint there. `node dist/http.js` still starts HTTP or falls through
// to stdio when MCP_TRANSPORT is not http.
if (process.env.VITEST !== 'true') {
  if (process.env.MCP_TRANSPORT === 'http') {
    startHttpServer().catch((error: unknown) => {
      logger.error('Fatal startup error', {
        error: error instanceof Error ? error.message : String(error),
      });
      process.exit(1);
    });
  } else {
    void import('./index.js');
  }
}
