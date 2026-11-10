# Advisory 7 - Hardcoded Credentials and Embedded Key Material

| Field | Value |
|---|---|
| **Advisory** | 7 of 8 (see the [findings index](../README.md)) |
| **Weakness** |  Use of Hard-coded Credentials (CWE-798); Cleartext Storage of Sensitive Information (CWE-312) |
| **Affected** | Magnet FasTrak 1.17.3 for Windows |
| **Status** | Unpatched at time of publication |

## Description

The public binary build embeds credentials and private key material directly inside of the application. This includes a Datadog ingest key, Amplitude project keys, a Datadog RUM client token, the TLS key and certificate, as well as the ADB keys used for communicating with the device. This information could be used to send false data to Magnet's analytics provider, and also hands anyone with access to the internet the keys they use for adb communication with smartphones.

## 1 - Datadog log-ingest API key (main process)

The log-forwarding function sends every info and error log line to Datadog with a hardcoded ingest key in the request header (`main/main.ts:348`):

```ts
headers: {
  'Content-Type': 'application/json',
  'DD-API-KEY': 'redacted',
},
```

This gives anyone the ability to inject or forge log events into Magnet's Datadog intake.

## 2 - Amplitude project keys and Datadog RUM client token (preload / renderer)

Two Amplitude keys (production and development) are compiled into the preload (`main/preload.ts:10`):

```ts
const amplitudeApiKey = process.env.PROD_BUILD === 'true'
  ? '<redacted - prod key>'
  : '<redacted - dev key>'
```

and the Datadog RUM client token is in the renderer (`renderer/hooks/useAnalytics.ts:33`).

## 3 - TLS client key and certificate, and ADB keys shipped in the build

The TLS client key and certificate used for the agent connection are read from the installed resources at runtime (`lib/Configuration.ts:445`):

```ts
const configureSSL = () => {
  const certPath = `${process.resourcesPath}\\auth\\cert`
  if (fs.existsSync(certPath)) {
    const cert = fs.readFileSync(certPath, 'utf8')
    set('sslCert', cert)                 // ← shipped client cert loaded into settings
  }
  // …identical block for `${process.resourcesPath}\\auth\\key` → set('sslKey', key)
}
```

These keys are then used at `lib/AndroidConnection.ts:50` / `lib/IOSConnection.ts:65`. ADB private/public keys are likewise shipped under `auth/ft_adb` and injected into the user's `.android` directory (`lib/Configuration.ts:533`):

```ts
const adbPrivateKeyPath = `${process.resourcesPath}\\auth\\ft_adb\\adbkey`
if (fs.existsSync(adbPrivateKeyPath)) {
  privateKey = fs.readFileSync(adbPrivateKeyPath, 'utf8')   // <- their shipped ADB private key
}

```
All of this key material travels inside the downloadable installer that is publicly accessible to anyone on the internet, so it is shared across every deployment and recoverable by anyone.

## Impact
Exposed, public credentials allow attackers to abuse Magnet's logging and analytics infrastructure through forged or flooded telemetry. Shared TLS client material and ADB keys stored on disk undermine security controls that rely on the confidentiality of this material. The telemetry keys primarily affect Magnet's own internal infrastructure.
