import { getTranscript } from './tools/transcript';

export interface Env {
  TRANSCRIPT_CACHE: KVNamespace;
  ACCESS_PASSWORD: string;
}

const CORS: Record<string, string> = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Cache-Control, Accept, Authorization',
};

function baseUrl(req: Request): string {
  const u = new URL(req.url);
  return `${u.protocol}//${u.host}`;
}

function rand(n = 32): string {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}

async function verifyPkce(verifier: string, challenge: string): Promise<boolean> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(digest)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return b64 === challenge;
}

async function validToken(req: Request, env: Env): Promise<boolean> {
  const h = req.headers.get('Authorization') ?? '';
  if (!h.startsWith('Bearer ')) return false;
  return (await env.TRANSCRIPT_CACHE.get(`oauth:tok:${h.slice(7)}`)) !== null;
}

function jsonResp(body: unknown, status = 200, extra?: Record<string, string>): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS, ...extra },
  });
}

function oauthMeta(req: Request): Response {
  const b = baseUrl(req);
  return jsonResp({
    issuer: b,
    authorization_endpoint: `${b}/oauth/authorize`,
    token_endpoint: `${b}/oauth/token`,
    registration_endpoint: `${b}/oauth/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['none', 'client_secret_post'],
  });
}

async function oauthRegister(req: Request, env: Env): Promise<Response> {
  let body: any = {};
  try { body = await req.json(); } catch {}
  const clientId = rand(16);
  const clientSecret = rand(32);
  await env.TRANSCRIPT_CACHE.put(
    `oauth:client:${clientId}`,
    JSON.stringify({ clientId, clientSecret, redirectUris: body.redirect_uris ?? [] }),
    { expirationTtl: 365 * 24 * 3600 },
  );
  return jsonResp({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: body.redirect_uris ?? [],
    token_endpoint_auth_method: 'none',
  }, 201);
}

function authorizeForm(req: Request, showError = false): Response {
  const u = new URL(req.url);
  const errHtml = showError
    ? '<p class="err">Incorrect password - try again.</p>'
    : '';
  const html = '<!DOCTYPE html>\n'
    + '<html lang="en"><head>\n'
    + '<meta charset="utf-8">\n'
    + '<title>Authorize - YouTube Transcript MCP</title>\n'
    + '<style>*{box-sizing:border-box}body{font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;background:#f5f5f5}.card{background:#fff;padding:2rem;border-radius:12px;box-shadow:0 4px 24px rgba(0,0,0,.1);width:100%;max-width:380px}h1{margin:0 0 .5rem;font-size:1.25rem}p{margin:0 0 1.5rem;color:#666;font-size:.9rem}input{width:100%;padding:.75rem;border:1px solid #ddd;border-radius:8px;font-size:1rem;margin-bottom:.75rem;outline:none}input:focus{border-color:#0070f3}button{width:100%;padding:.75rem;background:#0070f3;color:#fff;border:none;border-radius:8px;font-size:1rem;cursor:pointer;font-weight:500}button:hover{background:#005fcc}.err{color:#c00;font-size:.875rem;margin-bottom:.75rem;padding:.5rem;background:#fff0f0;border-radius:6px}</style>\n'
    + '</head><body><div class="card">\n'
    + '  <h1>YouTube Transcript MCP</h1>\n'
    + '  <p>Enter your access password to authorize this client.</p>\n'
    + '  ' + errHtml + '\n'
    + '  <form method="POST" action="/oauth/authorize' + u.search + '">\n'
    + '    <input type="password" name="password" placeholder="Access password" autofocus required>\n'
    + '    <button type="submit">Authorize</button>\n'
    + '  </form>\n'
    + '</div></body></html>';
  return new Response(html, { headers: { 'Content-Type': 'text/html' } });
}

async function oauthAuthorize(req: Request, env: Env): Promise<Response> {
  const u = new URL(req.url);
  const clientId      = u.searchParams.get('client_id')      ?? '';
  const redirectUri   = u.searchParams.get('redirect_uri')   ?? '';
  const state         = u.searchParams.get('state')          ?? '';
  const codeChallenge = u.searchParams.get('code_challenge') ?? '';

  if (req.method === 'GET') {
    return authorizeForm(req, u.searchParams.has('error'));
  }

  if (req.method === 'POST') {
    let password = '';
    try {
      const fd = await req.formData();
      password = (fd.get('password') as string) ?? '';
    } catch {
      return new Response('Bad Request', { status: 400 });
    }

    if (!env.ACCESS_PASSWORD || password !== env.ACCESS_PASSWORD) {
      const next = new URLSearchParams(u.search);
      next.set('error', '1');
      return Response.redirect(`${baseUrl(req)}/oauth/authorize?${next}`, 302);
    }

    const code = rand(32);
    await env.TRANSCRIPT_CACHE.put(
      `oauth:code:${code}`,
      JSON.stringify({ clientId, redirectUri, codeChallenge }),
      { expirationTtl: 300 },
    );

    const dest = new URL(redirectUri);
    dest.searchParams.set('code', code);
    if (state) dest.searchParams.set('state', state);
    return Response.redirect(dest.toString(), 302);
  }

  return new Response('Method Not Allowed', { status: 405 });
}

async function oauthToken(req: Request, env: Env): Promise<Response> {
  let params: URLSearchParams;
  try {
    params = new URLSearchParams(await req.text());
  } catch {
    return jsonResp({ error: 'invalid_request' }, 400);
  }

  if (params.get('grant_type') !== 'authorization_code') {
    return jsonResp({ error: 'unsupported_grant_type' }, 400);
  }

  const code = params.get('code') ?? '';
  const raw  = await env.TRANSCRIPT_CACHE.get(`oauth:code:${code}`);
  if (!raw) return jsonResp({ error: 'invalid_grant', error_description: 'Code not found or expired' }, 400);

  const { codeChallenge } = JSON.parse(raw) as { codeChallenge: string };
  const verifier = params.get('code_verifier') ?? '';
  if (codeChallenge && verifier) {
    if (!(await verifyPkce(verifier, codeChallenge))) {
      return jsonResp({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);
    }
  }

  await env.TRANSCRIPT_CACHE.delete(`oauth:code:${code}`);

  const token = rand(48);
  await env.TRANSCRIPT_CACHE.put(`oauth:tok:${token}`, '1', { expirationTtl: 30 * 24 * 3600 });

  return jsonResp({ access_token: token, token_type: 'Bearer', expires_in: 30 * 24 * 3600 });
}

class SimpleMCPServer {
  constructor(private env: Env) {}

  async handleRequest(request: any) {
    const { method, params, id } = request;

    try {
      switch (method) {
        case 'initialize':
          return {
            jsonrpc: '2.0', id,
            result: {
              protocolVersion: '2024-11-05',
              capabilities: { tools: {} },
              serverInfo: { name: 'youtube-transcript-remote', version: '1.0.0' },
            },
          };

        case 'tools/list':
          return {
            jsonrpc: '2.0', id,
            result: {
              tools: [{
                name: 'get_transcript',
                description: 'Extract transcript from YouTube video URL',
                inputSchema: {
                  type: 'object',
                  properties: {
                    url:      { type: 'string', description: 'YouTube video URL (any format)' },
                    language: { type: 'string', description: "Language code e.g. 'en', 'es'. Defaults to 'en'." },
                  },
                  required: ['url'],
                },
              }],
            },
          };

        case 'tools/call': {
          const { name, arguments: args } = params;
          if (name === 'get_transcript') {
            try {
              const { url, language = 'en' } = args;
              const transcript = await getTranscript(url, this.env, language);
              return { jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: transcript }] } };
            } catch (error) {
              return {
                jsonrpc: '2.0', id,
                error: { code: -1, message: error instanceof Error ? error.message : 'Unknown error' },
              };
            }
          }
          return { jsonrpc: '2.0', id, error: { code: -32601, message: `Unknown tool: ${name}` } };
        }

        default:
          return { jsonrpc: '2.0', id, error: { code: -32601, message: `Method not found: ${method}` } };
      }
    } catch (error) {
      console.error('Error handling request:', error);
      return { jsonrpc: '2.0', id, error: { code: -32603, message: 'Internal error' } };
    }
  }
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS });
    }

    if (url.pathname === '/.well-known/oauth-authorization-server') return oauthMeta(request);
    if (url.pathname === '/oauth/register' && request.method === 'POST') return oauthRegister(request, env);
    if (url.pathname === '/oauth/authorize') return oauthAuthorize(request, env);
    if (url.pathname === '/oauth/token' && request.method === 'POST') return oauthToken(request, env);

    if (url.pathname === '/sse' || url.pathname === '/mcp') {
      if (!(await validToken(request, env))) {
        return new Response(JSON.stringify({ error: 'unauthorized' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json', 'WWW-Authenticate': 'Bearer', ...CORS },
        });
      }
    }

    const mcpServer = new SimpleMCPServer(env);

    if (url.pathname === '/sse') {
      if (request.method === 'POST') {
        try {
          const response = await mcpServer.handleRequest(await request.json());
          return new Response('data: ' + JSON.stringify(response) + '\n\n', {
            headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...CORS },
          });
        } catch {
          return new Response('data: ' + JSON.stringify({ jsonrpc:'2.0',id:null,error:{code:-32603,message:'Internal error'} }) + '\n\n', {
            headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', ...CORS },
          });
        }
      }

      const { readable, writable } = new TransformStream();
      const writer  = writable.getWriter();
      const encoder = new TextEncoder();
      ctx.waitUntil((async () => {
        try {
          await writer.write(encoder.encode('data: ' + JSON.stringify({ jsonrpc:'2.0',method:'notifications/initialized',params:{} }) + '\n\n'));
          const ka = setInterval(() => writer.write(encoder.encode(': keepalive\n\n')).catch(() => clearInterval(ka)), 30000);
        } catch (e) { console.error('SSE stream error:', e); }
      })());
      return new Response(readable, {
        headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', ...CORS },
      });
    }

    if (url.pathname === '/mcp' && request.method === 'POST') {
      try {
        const response = await mcpServer.handleRequest(await request.json());
        return new Response(JSON.stringify(response), {
          headers: { 'Content-Type': 'application/json', ...CORS },
        });
      } catch {
        return new Response(JSON.stringify({ jsonrpc:'2.0',id:null,error:{code:-32603,message:'Internal error'} }), {
          status: 500,
          headers: { 'Content-Type': 'application/json', ...CORS },
        });
      }
    }

    if (url.pathname === '/') {
      return new Response(JSON.stringify({
        name: 'YouTube Transcript Remote MCP Server',
        version: '1.0.0',
        endpoints: { sse: '/sse', mcp: '/mcp' },
        tools: ['get_transcript'],
        status: 'ready',
        auth: 'OAuth 2.0 (Authorization Code + PKCE)',
      }), { headers: { 'Content-Type': 'application/json', ...CORS } });
    }

    return new Response('Not Found', { status: 404 });
  },
};