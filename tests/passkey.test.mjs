import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

globalThis.atob = (value) => Buffer.from(value, 'base64').toString('binary');
globalThis.btoa = (value) => Buffer.from(value, 'binary').toString('base64');
globalThis.window = { PublicKeyCredential: function PublicKeyCredential() {} };

const source = await readFile(new URL('../assets/passkey.js', import.meta.url), 'utf8');
const { registerPasskey, loginWithPasskey } = await import(
  `data:text/javascript,${encodeURIComponent(source)}`
);

const jsonResponse = (value, ok = true, status = 200) => ({
  ok,
  status,
  async json() {
    if (value instanceof Error) throw value;
    return value;
  },
});

test('registration maps binary fields and nests transports in response', async () => {
  const requests = [];
  globalThis.fetch = async (url, init) => {
    requests.push({ url, init, body: JSON.parse(init.body) });
    return requests.length === 1
      ? jsonResponse({ challenge: 'AQ', user: { id: 'Ag' }, excludeCredentials: [] })
      : jsonResponse({ ok: true });
  };
  Object.defineProperty(globalThis, 'navigator', { configurable: true, writable: true, value: {
    credentials: {
      async create() {
        return {
          id: 'credential-id',
          rawId: Uint8Array.from([3]).buffer,
          type: 'public-key',
          response: {
            clientDataJSON: Uint8Array.from([4]).buffer,
            attestationObject: Uint8Array.from([5]).buffer,
            getTransports: () => ['internal'],
          },
        };
      },
    },
  } });

  assert.deepEqual(await registerPasskey('/begin', '/finish', 'csrf', 'Laptop'), { ok: true });
  assert.deepEqual(requests[1].body.response.transports, ['internal']);
  assert.equal('transports' in requests[1].body, false);
  assert.equal(requests[1].body.rawId, 'Aw');
  assert.equal(requests[1].init.headers['X-CSRF-Token'], 'csrf');
});

test('successful non-JSON responses become structured errors', async () => {
  globalThis.fetch = async () => jsonResponse(new Error('not json'));
  Object.defineProperty(globalThis, 'navigator', { configurable: true, writable: true, value: {
    credentials: { async get() { throw new Error('unreached'); } },
  } });

  const result = await loginWithPasskey('/begin', '/finish');
  assert.deepEqual(result, { ok: false, error: 'Invalid server response.' });
});
