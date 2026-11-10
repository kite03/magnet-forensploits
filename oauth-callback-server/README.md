# Advisory 8 - Permissive Origin Handling in OAuth Callback Server

| Field | Value |
|---|---|
| **Advisory** | 8 of 8 (see the [findings index](../README.md)) |
| **Weakness** | CWE-346 / CWE-942: control channels accept and distribute messages without validating their origin, CWE-330: the CSRF `state` - the primary barrier to a forged callback is generated with `Math.random()` |
| **Affected** | Magnet FasTrak 1.17.3 for Windows |
| **Status** | Unpatched at time of publication |

## Description

FasTrak's local OAuth callback server answers every request with wildcard CORS and relays the data to the renderer with `postMessage(..., '*')`. This means that there is no target-origin restriction, and the application also exposes a POST endpoint that allows an attacker to forward arbitrary JSON into the program as an `oauth-callback`. While the server is running, any web origin the examiner visits or local process can interact with it and inject a forged callback. The actual application uses a `magnetoneapp://` custom-scheme redirect, so the localhost server is not started during routine login; but the renderer can start it via an exposed IPC.

## Wildcard CORS on every response

```ts
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
```
`main/main.ts:463`

## Callback data broadcast with no target origin

The served callback page posts the OAuth result with a `'*'` target origin by every available
channel (`main/main.ts:503`, `:508`, `:516`):

```ts
window.opener.postMessage(callbackData, '*');
...
window.parent.postMessage(callbackData, '*');
...
window.postMessage(callbackData, '*');
```

and `postMessage(..., '*')` places no restriction on which origin may receive the message.

## POST endpoint forwards arbitrary JSON into the app

```ts
} else if (req.url === '/auth-callback' && req.method === 'POST') {
  ...
  const callbackData = JSON.parse(body);
  if (mainWindow) {
    mainWindow.webContents.send('oauth-callback', callbackData);
  }
```
`main/main.ts:542`

Anything that can POST to `http://localhost:3000/auth-callback` while the server is up can inject a crafted `oauth-callback` into the renderer.

## The server is reachable via an exposed IPC

`start-callback-server` is registered as an IPC handler (`main/main.ts:453`) and surfaced to the renderer through the client API, so the localhost server can be brought up at any time, not only during a localhost dev redirect.

## The renderer accepts callback messages without an origin check

On the receiving side, the renderer's `message` listener processes any `OAUTH_CALLBACK` message regardless of where it came from (handler at `renderer/providers/AuthProvider/AuthProvider.tsx:263`, registered at `:330`):

```ts
const handleMessage = (event: any) => {
  if (event.data && event.data.type === 'OAUTH_CALLBACK') {
    processCallback(event.data, resolve, reject)   // no event.origin check
  }
}
window.addEventListener('message', handleMessage)
```

The same `processCallback` is also reachable from the production flow: any site can trigger `magnetoneapp://oauth/callback?code=...&state=...`, which the main process parses and forwards to the renderer as an `oauth-callback` (`main/main.ts:94`):

```ts
const callbackData = {
  type: 'OAUTH_CALLBACK',
  code: params.get('code'),
  state: params.get('state'),
  ...
};
if (mainWindow && mainWindow.webContents) {
  mainWindow.webContents.send('oauth-callback', callbackData);   // ← straight to the renderer
}
```

Both inlets are protected only by a `state` comparison (`AuthProvider.tsx:296`) - and that `state` is generated with `Math.random()` (`AuthProvider.tsx:234`), not a cryptographic RNG (**CWE-330**):

```ts
const state = Math.random().toString(36).substring(2, 15);   // ← CSRF state, not crypto-random
localStorage.setItem('oauth-state', state);
```

The PKCE `code_verifier` elsewhere in the same file correctly uses `crypto.getRandomValues`, but it is then embedded in the same `state` value (`AuthProvider.tsx:238`) and read back from the callback (`:319`), so it travels through the browser alongside the authorization code.


## Impact
A malicious local process or web page open in the examiner’s browser could inject a forged OAuth callback while the callback server is running, potentially causing token confusion or leaking the authorization code, along with the PKCE verifier carried in `state`, through cross-origin broadcasts. The impact is limited, however, by the fact that the localhost server is not started during normal production sign-in. The actual attack surfaces are the custom-scheme deep link and the renderer’s unauthenticated message listener, which accept OAUTH_CALLBACK messages from any origin. Both rely on validating OAuth state against localStorage, so exploitation requires satisfying or bypassing this check, made more feasible by the insecure `Math.random()` state generation.

