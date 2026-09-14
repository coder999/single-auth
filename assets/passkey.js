// Browser half of the WebAuthn ceremonies. Protocol plumbing only: it
// renders nothing and styles nothing, so it does not contradict
// single-auth shipping no login-page HTML.
//
// Consumers cannot serve this file directly -- every site's nginx denies
// /vendor/ -- so each one serves it through a small PHP passthrough.

const b64uToBytes = (s) => {
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/') + pad);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

const bytesToB64u = (buf) => {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

export const isSupported = () =>
  typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function';

const invalidResponse = () => ({ ok: false, error: 'Invalid server response.' });

const postJson = async (url, body, csrfToken) => {
  const headers = { 'Content-Type': 'application/json' };
  if (csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const res = await fetch(url, {
    method: 'POST',
    headers,
    credentials: 'same-origin',
    body: JSON.stringify(body),
  });

  let data;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok) {
    return {
      ok: false,
      error: data && typeof data === 'object' && typeof data.error === 'string'
        ? data.error
        : `HTTP ${res.status}`,
    };
  }

  return data && typeof data === 'object' && !Array.isArray(data)
    ? data
    : invalidResponse();
};

const finishResult = (data) =>
  data && typeof data === 'object' && !Array.isArray(data) && typeof data.ok === 'boolean'
    ? data
    : invalidResponse();

export async function registerPasskey(beginUrl, finishUrl, csrfToken, label) {
  if (!isSupported()) return { ok: false, error: 'This browser does not support passkeys.' };
  try {
    const options = await postJson(beginUrl, { label }, csrfToken);
    if (options.ok === false) return finishResult(options);

    options.challenge = b64uToBytes(options.challenge);
    options.user.id = b64uToBytes(options.user.id);
    (options.excludeCredentials || []).forEach((c) => { c.id = b64uToBytes(c.id); });

    const cred = await navigator.credentials.create({ publicKey: options });
    if (!cred || !cred.response) return invalidResponse();
    return finishResult(await postJson(finishUrl, {
      id: cred.id,
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
        attestationObject: bytesToB64u(cred.response.attestationObject),
        transports: cred.response.getTransports ? cred.response.getTransports() : [],
      },
    }, csrfToken));
  } catch (e) {
    // NotAllowedError is the user cancelling or timing out, not a fault.
    if (e.name === 'NotAllowedError') return { ok: false, error: 'Cancelled.' };
    return { ok: false, error: e.message || 'Passkey registration failed.' };
  }
}

export async function loginWithPasskey(beginUrl, finishUrl) {
  if (!isSupported()) return { ok: false, error: 'This browser does not support passkeys.' };
  try {
    const options = await postJson(beginUrl, {});
    if (options.ok === false) return finishResult(options);

    options.challenge = b64uToBytes(options.challenge);
    (options.allowCredentials || []).forEach((c) => { c.id = b64uToBytes(c.id); });

    const cred = await navigator.credentials.get({ publicKey: options });
    if (!cred || !cred.response) return invalidResponse();
    return finishResult(await postJson(finishUrl, {
      id: cred.id,
      rawId: bytesToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64u(cred.response.clientDataJSON),
        authenticatorData: bytesToB64u(cred.response.authenticatorData),
        signature: bytesToB64u(cred.response.signature),
        userHandle: cred.response.userHandle ? bytesToB64u(cred.response.userHandle) : null,
      },
    }));
  } catch (e) {
    if (e.name === 'NotAllowedError') return { ok: false, error: 'Cancelled.' };
    return { ok: false, error: e.message || 'Passkey login failed.' };
  }
}
