/**
 * HTTP transport fail-closed auth.
 *
 * Startup requires a real CONDUIT_S2S_SECRET unless MCP_ALLOW_INSECURE_DEV=1.
 * Known placeholders are refused even with that flag. The flag binds
 * 127.0.0.1 only. AUTH_MODE=gateway rejects /mcp requests that omit
 * X-DNSFilter-Api-Key and must not fall back to DNSFILTER_API_KEY.
 */
import { createHmac } from 'node:crypto';
import { request as httpRequest, type Server } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { startHttpServer } from '../http.js';

const S2S_SECRET = 'test-s2s-secret-do-not-log';
const ENV_API_KEY = 'env-key-should-not-be-used';
const HEADER_API_KEY = 'header-key-from-gateway';

const ENV_KEYS = [
  'CONDUIT_S2S_SECRET',
  'MCP_ALLOW_INSECURE_DEV',
  'MCP_HTTP_PORT',
  'MCP_HTTP_HOST',
  'AUTH_MODE',
  'DNSFILTER_API_KEY',
  'LOG_LEVEL',
  'MCP_TRANSPORT',
] as const;

const savedEnv = new Map<string, string | undefined>(ENV_KEYS.map((key) => [key, process.env[key]]));
const servers: Server[] = [];

function mintS2sHeader(secret: string, unixSeconds = Math.floor(Date.now() / 1000)): string {
  const message = `t=${unixSeconds}`;
  const hex = createHmac('sha256', secret).update(message).digest('hex');
  return `${message},v1=${hex}`;
}

function restoreEnv(): void {
  for (const key of ENV_KEYS) {
    const value = savedEnv.get(key);
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  restoreEnv();
  while (servers.length > 0) {
    const server = servers.pop();
    if (!server) continue;
    await new Promise<void>((resolve, reject) => {
      if (!server.listening) {
        resolve();
        return;
      }
      server.close((err) => (err ? reject(err) : resolve()));
    });
  }
});

function silenceLogs(): { text: () => string } {
  const lines: string[] = [];
  vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => (typeof arg === 'string' ? arg : JSON.stringify(arg))).join(' '));
  });
  return { text: () => lines.join('\n') };
}

function exitSpy() {
  return vi.spyOn(process, 'exit').mockImplementation(((code?: number) => {
    throw new Error(`process.exit:${code}`);
  }) as typeof process.exit);
}

function assertNoSecrets(logged: string, extra: string[] = []): void {
  expect(logged).not.toContain(S2S_SECRET);
  expect(logged).not.toContain(ENV_API_KEY);
  expect(logged).not.toContain(HEADER_API_KEY);
  for (const value of extra) expect(logged).not.toContain(value);
}

async function listenPort(server: Server): Promise<number> {
  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('expected the HTTP server to bind a TCP port');
  }
  return address.port;
}

function mcpHeaders(extra: Record<string, string> = {}): Record<string, string> {
  return {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    ...extra,
  };
}

interface HttpResult {
  status: number;
  body: string;
}

/** node:http client so a stubbed global fetch cannot swallow the test request. */
function sendHttp(options: {
  port: number;
  method: string;
  path: string;
  headers?: Record<string, string>;
  body?: string;
}): Promise<HttpResult> {
  return new Promise((resolve, reject) => {
    const req = httpRequest(
      {
        hostname: '127.0.0.1',
        port: options.port,
        method: options.method,
        path: options.path,
        headers: options.headers,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk: Buffer) => chunks.push(chunk));
        res.on('end', () => {
          resolve({
            status: res.statusCode ?? 0,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      }
    );
    req.setTimeout(5000, () => {
      req.destroy(new Error(`timeout ${options.method} ${options.path}`));
    });
    req.on('error', reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

const listOrganizationsCall = {
  jsonrpc: '2.0',
  id: 1,
  method: 'tools/call',
  params: { name: 'dnsfilter_list_organizations', arguments: {} },
};

describe('HTTP startup fails closed without a real CONDUIT_S2S_SECRET', () => {
  it('logs an error and exits non-zero when the secret is empty', async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.DNSFILTER_API_KEY = ENV_API_KEY;
    process.env.LOG_LEVEL = 'error';
    const logs = silenceLogs();
    const exit = exitSpy();

    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(exit).toHaveBeenCalledWith(1);
    const logged = logs.text();
    expect(logged).toContain('Refusing to start HTTP server: CONDUIT_S2S_SECRET is empty.');
    expect(logged).toContain('MCP_ALLOW_INSECURE_DEV=1');
    assertNoSecrets(logged);
  });

  it('still exits when the secret is whitespace or MCP_ALLOW_INSECURE_DEV is not exactly 1', async () => {
    process.env.CONDUIT_S2S_SECRET = '   ';
    process.env.MCP_ALLOW_INSECURE_DEV = 'true';
    process.env.LOG_LEVEL = 'error';
    const logs = silenceLogs();
    exitSpy();

    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(logs.text()).toContain('CONDUIT_S2S_SECRET is empty');
    assertNoSecrets(logs.text());
  });

  it('refuses a known placeholder secret and does not log it', async () => {
    process.env.CONDUIT_S2S_SECRET = 'replace-with-a-real-secret';
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.LOG_LEVEL = 'error';
    const logs = silenceLogs();
    const exit = exitSpy();

    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    expect(exit).toHaveBeenCalledWith(1);
    const logged = logs.text();
    expect(logged).toContain('known placeholder');
    expect(logged).toContain('openssl rand -hex 32');
    expect(logged).not.toContain('replace-with-a-real-secret');
    assertNoSecrets(logged);
  });

  it('refuses a placeholder even when MCP_ALLOW_INSECURE_DEV=1', async () => {
    process.env.CONDUIT_S2S_SECRET = '  Your-S2S-Secret  ';
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.LOG_LEVEL = 'error';
    const logs = silenceLogs();
    exitSpy();

    await expect(startHttpServer()).rejects.toThrow('process.exit:1');
    const logged = logs.text();
    expect(logged).toContain('known placeholder');
    expect(logged).not.toContain('Your-S2S-Secret');
    assertNoSecrets(logged);
  });

  it('starts with a loud warning and binds 127.0.0.1 when MCP_ALLOW_INSECURE_DEV=1', async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    delete process.env.MCP_HTTP_HOST;
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.DNSFILTER_API_KEY = ENV_API_KEY;
    process.env.LOG_LEVEL = 'error';
    const logs = silenceLogs();
    const exit = exitSpy();

    const server = await startHttpServer();
    servers.push(server);

    expect(exit).not.toHaveBeenCalled();
    const logged = logs.text();
    expect(logged).toContain('WARNING:');
    expect(logged).toContain('MCP_ALLOW_INSECURE_DEV=1');
    expect(logged).toContain('WITHOUT service-to-service authentication');
    expect(logged).toContain('127.0.0.1');
    assertNoSecrets(logged);
    expect(server.address()).toMatchObject({ address: '127.0.0.1' });
  });

  it('forces 127.0.0.1 when the dev bypass is set and MCP_HTTP_HOST is non-loopback', async () => {
    delete process.env.CONDUIT_S2S_SECRET;
    process.env.MCP_ALLOW_INSECURE_DEV = '1';
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    process.env.MCP_HTTP_PORT = '0';
    process.env.LOG_LEVEL = 'error';
    const logs = silenceLogs();
    const exit = exitSpy();

    const server = await startHttpServer();
    servers.push(server);

    expect(exit).not.toHaveBeenCalled();
    const logged = logs.text();
    expect(logged).toContain('MCP_HTTP_HOST=0.0.0.0 is not 127.0.0.1');
    expect(logged).toContain('Binding 127.0.0.1 only');
    assertNoSecrets(logged);
    expect(server.address()).toMatchObject({ address: '127.0.0.1' });
  });

  it('honors a non-loopback MCP_HTTP_HOST when a real secret is set', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.MCP_HTTP_HOST = '0.0.0.0';
    process.env.MCP_HTTP_PORT = '0';
    process.env.LOG_LEVEL = 'info';
    const logs = silenceLogs();

    const server = await startHttpServer();
    servers.push(server);

    const logged = logs.text();
    expect(logged).not.toContain('not 127.0.0.1');
    expect(logged).toContain('listening on 0.0.0.0:');
    assertNoSecrets(logged);
    expect(server.address()).toMatchObject({ address: '0.0.0.0' });
  });

  it('defaults the bind address to 127.0.0.1 when a secret is set and MCP_HTTP_HOST is unset', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    delete process.env.MCP_HTTP_HOST;
    process.env.MCP_HTTP_PORT = '0';
    process.env.LOG_LEVEL = 'info';
    const logs = silenceLogs();

    const server = await startHttpServer();
    servers.push(server);

    expect(logs.text()).toContain('listening on 127.0.0.1:');
    assertNoSecrets(logs.text());
    expect(server.address()).toMatchObject({ address: '127.0.0.1' });
  });
});

describe('gateway /mcp auth', () => {
  async function startGateway(): Promise<number> {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.AUTH_MODE = 'gateway';
    process.env.DNSFILTER_API_KEY = ENV_API_KEY;
    process.env.LOG_LEVEL = 'error';
    silenceLogs();
    const server = await startHttpServer();
    servers.push(server);
    return listenPort(server);
  }

  function postMcp(port: number, headers: Record<string, string>): Promise<HttpResult> {
    return sendHttp({
      port,
      method: 'POST',
      path: '/mcp',
      headers: mcpHeaders(headers),
      body: JSON.stringify(listOrganizationsCall),
    });
  }

  it('returns 401 when the S2S header is missing or invalid and does not call DNSFilter', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const port = await startGateway();

    const missing = await postMcp(port, { 'x-dnsfilter-api-key': HEADER_API_KEY });
    expect(missing.status).toBe(401);
    const missingBody = JSON.parse(missing.body) as { error: string };
    expect(missingBody.error).toMatch(/X-Gateway-S2S/);

    const invalid = await postMcp(port, {
      'x-gateway-s2s': mintS2sHeader('wrong-secret'),
      'x-dnsfilter-api-key': HEADER_API_KEY,
    });
    expect(invalid.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(missing.body).not.toContain(ENV_API_KEY);
    expect(missing.body).not.toContain(S2S_SECRET);
    expect(missing.body).not.toContain(HEADER_API_KEY);
  });

  it('returns 401 in gateway mode when the credential header is missing and does not use env credentials', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const port = await startGateway();

    const response = await postMcp(port, { 'x-gateway-s2s': mintS2sHeader(S2S_SECRET) });
    expect(response.status).toBe(401);
    const body = JSON.parse(response.body) as { error: string; message: string; required: string[] };
    expect(body.error).toBe('Missing credentials');
    expect(body.message).toMatch(/X-DNSFilter-Api-Key/);
    expect(body.required).toEqual(['X-DNSFilter-Api-Key']);
    expect(fetchMock).not.toHaveBeenCalled();
    expect(response.body).not.toContain(ENV_API_KEY);
    expect(response.body).not.toContain(S2S_SECRET);
  });

  it('rejects a whitespace-only credential header in gateway mode', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const port = await startGateway();

    const response = await postMcp(port, {
      'x-gateway-s2s': mintS2sHeader(S2S_SECRET),
      'x-dnsfilter-api-key': '   ',
    });
    expect(response.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('accepts a valid S2S header plus the credential header and uses that key', async () => {
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) =>
      new Response(JSON.stringify({ data: [{ id: 'org-1' }] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );
    vi.stubGlobal('fetch', fetchMock);
    const port = await startGateway();

    const response = await postMcp(port, {
      'x-gateway-s2s': mintS2sHeader(S2S_SECRET),
      'x-dnsfilter-api-key': HEADER_API_KEY,
    });
    expect(response.status).toBe(200);
    const body = JSON.parse(response.body) as { result: { content: Array<{ text: string }> } };
    expect(JSON.parse(body.result.content[0].text).data[0].id).toBe('org-1');
    const dnsCall = fetchMock.mock.calls.find((call) => String(call[0]).includes('api.dnsfilter.com'));
    expect(dnsCall?.[1]?.headers).toMatchObject({ Authorization: HEADER_API_KEY });
    expect(response.body).not.toContain(ENV_API_KEY);
    expect(response.body).not.toContain(S2S_SECRET);
  });

  it('serves /health without authentication and without reading credentials', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const port = await startGateway();

    const response = await sendHttp({ port, method: 'GET', path: '/health' });
    const body = JSON.parse(response.body) as { status: string; credentials?: unknown };

    expect(response.status).toBe(200);
    expect(body.status).toBe('ok');
    expect(body.credentials).toBeUndefined();
    expect(response.body).not.toContain(ENV_API_KEY);
    expect(response.body).not.toContain(S2S_SECRET);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('uses DNSFILTER_API_KEY in env mode after a valid S2S header, without requiring the credential header', async () => {
    process.env.CONDUIT_S2S_SECRET = S2S_SECRET;
    delete process.env.MCP_ALLOW_INSECURE_DEV;
    process.env.MCP_HTTP_HOST = '127.0.0.1';
    process.env.MCP_HTTP_PORT = '0';
    process.env.AUTH_MODE = 'env';
    process.env.DNSFILTER_API_KEY = ENV_API_KEY;
    process.env.LOG_LEVEL = 'error';
    silenceLogs();
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit) =>
      new Response(JSON.stringify({ data: [] }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );
    vi.stubGlobal('fetch', fetchMock);
    const server = await startHttpServer();
    servers.push(server);
    const port = await listenPort(server);

    const response = await postMcp(port, { 'x-gateway-s2s': mintS2sHeader(S2S_SECRET) });
    expect(response.status).toBe(200);
    const dnsCall = fetchMock.mock.calls.find((call) => String(call[0]).includes('api.dnsfilter.com'));
    expect(dnsCall?.[1]?.headers).toMatchObject({ Authorization: ENV_API_KEY });
  });
});
