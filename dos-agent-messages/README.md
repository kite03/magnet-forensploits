# Advisory 6 - Denial of Service via Unvalidated Agent Messages

| Field | Value |
|---|---|
| **Advisory** | 6 of 8 (see the [findings index](../README.md)) |
| **Weakness** | Improper Input Validation (CWE-20), Uncaught Exception (CWE-248) and Uncontrolled Resource Consumption (CWE-400) |
| **Affected** | Magnet FasTrak 1.17.3 for Windows |
| **Status** | Unpatched at time of publication |

## Description

FasTrak parses agent messages with no error handling and no bounds. This means that if a message is not valid JSON, truncated or omits a field the code expects, the application throws an uncaught exception. A message whose header advertises a very large length makes FasTrak buffer without limit. This completely breaks processing for that device, and the application must be restarted. 

## Demonstration

![Advisory 6 demo](../assets/demo_adv6.gif)

Every chunk from the agent is passed straight to `handleMessage`, with no `try/catch` around it (`lib/AndroidConnection.ts:76`, and identically `lib/IOSConnection.ts:86`):

```ts
this.socket.on('data', async (data: Buffer) => {
  await this.handleMessage(data)
})
```

`handleMessage` is `async`, so any exceptions thrown become an unhandled promise rejection. There is no `.catch` or guard anywhere in this code.


```ts
const content = message.content.toString()
const deviceInfo = JSON.parse(content)
```
`lib/DeviceConnection.ts:143`

If the agent's hello body is not valid JSON, `JSON.parse` throws immediately. The same
unguarded `JSON.parse` pattern is repeated for other message types
(`lib/DeviceConnection.ts:180`, `:246`, `:286`, `:293`).


Right after parsing, the code assumes fields exist and have the right type
(`lib/DeviceConnection.ts:155`):

```ts
const agentVersion = deviceInfo['v']
const versionParts = agentVersion.split('.')
```

If the agent omits `v`, `agentVersion` is `undefined` and `.split` throws a `TypeError` -
again, uncaught.

The framing trusts a length the agent supplies, and accumulates data until that many bytes
arrive (`lib/DeviceConnection.ts:114`):

```ts
this.messageBuffer = Buffer.concat([this.messageBuffer, data] as any)
...
const messageLength = this.messageBuffer.readUInt32LE(1)
const contentEnd = messageLength + headerSize
if (contentEnd > this.messageBuffer.length) {
  return          // keep buffering until the declared length is reached
}
```

A header that advertises a large length while the agent continuously outputs random data keeps the buffer growing until the declared length (up to 4 GiB) is reached.

## Impact

An unauthorised attacker who is able to use agent protocol communication can disrupt operations by sending corrupted requests or allocating too much memory which disrupts software stability. This poses a risk for forensic acquisition reliability and availability, and if a device carrying a payload like this is connected, it would disrupt that device's acquisition.
