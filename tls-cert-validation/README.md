# Advisory 5 - Agent TLS Connection Disables Certificate Validation

| Field | Value |
|---|---|
| **Advisory** | 5 of 8 (see the [findings index](../README.md)) |
| **Weakness** | Improper Certificate Validation (CWE-295) |
| **Affected** | Magnet FasTrak 1.17.3 for Windows, Android and iOS acquisition paths |
| **Status** | Unpatched at time of publication |

## Description

FasTrak opens a TLS ("secure") connection to the on-device agent but tells TLS to accept any certificate. The handshake will complete with any peer, meaning an attacker can give the program a self-signed certificate. The channel is encrypted but it is not authenticated properly. This means that FasTrak has no assurance it is actually talking to the real agent. This is a weakness in its own right, and it makes exploitation significantly easier within this software.

## The code

Both connection paths set up TLS the same way. Android (`lib/AndroidConnection.ts:47`):

```ts
if (this.socketPort) {
  log.info(`attempting to connect to android device: ${this.id}`)
  const connectionOptions = {
    key: Configuration.SSLKey(),
    cert: Configuration.SSLCert(),
    rejectUnauthorized: false,
  }

  this.socket = tls.connect(this.socketPort, '127.0.0.1', connectionOptions, () => {
    log.info(`Socket connection established with android device: ${this.id}`)
```

iOS (`lib/IOSConnection.ts:64`):

```ts
const connectionOptions = {
  key: Configuration.SSLKey(),
  cert: Configuration.SSLCert(),
  rejectUnauthorized: false,
}
this.socket = tls.connect(this.socketPort, '127.0.0.1', connectionOptions, () => {
  log.info(`Socket connection established with ios device: ${this.id}`)
```

Note the line: `rejectUnauthorized: false`. This means that when FasTrak connects, the agent's certificate is not validated and therefore is untrusted. This allows an attacker to impersonate the on-device agent even more easily, without key material.
## Impact
Not verifying the certificate provided by the agent lowers the bar for every agent-based exploit in this repository. It allows an attacker to impersonate the agent, or man-in-the-middle the connection, without owning any legitimate key material. An attacker would not be able to impersonate the agent's communication easily without the key used for communication, but because `rejectUnauthorized: false` is set, an attacker can simply create their own key to exploit this program. In fact, the iOS demonstrations in this repository were performed with a self-signed certificate, while the Android demonstrations reused the certificate shipped with FasTrak.
