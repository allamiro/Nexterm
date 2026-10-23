# SSH certificates

Nexterm can present an OpenSSH user certificate when it opens an SSH session, and it can ask a certificate authority for a short-lived certificate at connection time.

Uploaded certificates are the static case: an identity keeps its private key and an optional certificate. Short-lived certificates replace that key for one session. The session key is generated in memory, signed, and discarded when the request that opened the session finishes. It is not written to the identity store.

## Static certificates

An SSH or key-and-password identity accepts an optional OpenSSH user certificate (`*-cert.pub`). The certificate is stored with the identity's other secrets. SSH, SFTP, tunnels, and the remote browser pass it to the engine with the private key. The engine presents the certificate as the public key during public-key authentication.

A certificate is optional. A server that requires certificate authentication will reject a key that has none.

## Short-lived certificates

An administrator creates a certificate authority under Settings → SSH Certificates. It can apply to every server or to one organization. A server's settings can then select that authority. When the server is selected, the next SSH, SFTP, tunnel, or remote-browser connection does this:

1. Generate an Ed25519 key for that connection.
2. Build the principal list from the identity username, extra principals on the authority, and group mappings.
3. Ask the authority to sign a user certificate.
4. Authenticate with that key and certificate instead of the stored key or password.
5. Record the authority, key id, serial, principals, validity, and source address. The private key is not recorded.

Group mappings use the groups saved from the last OpenID Connect login. A mapping line `linux-admins=root,ubuntu` adds those principals when the signed-in account has the group `linux-admins`. The identity username is always included.

The source address, when set, becomes the certificate's `source-address` restriction. That address is the address the SSH server sees, which is the engine's address, not the browser's address. Leave it empty when the engine address changes.

Supported authorities:

| Backend | What Nexterm stores | Request |
| --- | --- | --- |
| Local CA key | Unencrypted Ed25519 OpenSSH or PKCS#8 private key | Signed inside Nexterm |
| Vault SSH | Address, mount, role, and token | `POST /v1/{mount}/sign/{role}` |
| step-ca | URL and either a one-time token or a bearer token | `POST /ssh/sign` |
| Webhook | URL and optional bearer token | JSON shown below |

Webhook body:

```json
{
  "publicKey": "ssh-ed25519 AAAA... nexterm-session",
  "principals": ["alice"],
  "keyId": "alice",
  "ttlSeconds": 300,
  "validAfter": "2026-01-01T00:00:00.000Z",
  "validBefore": "2026-01-01T00:05:00.000Z",
  "sourceAddress": "10.0.0.8/32",
  "certType": "user"
}
```

The response is JSON with `certificate`, `crt`, or `signed_key`, or the certificate text itself. Lifetime is limited to between 30 seconds and 24 hours. The default is 5 minutes.

The key id template accepts `{{username}}`, `{{account}}`, `{{server}}`, and `{{host}}`.

An authority with an organization can only sign for servers in that organization. An authority without an organization can sign for any server.

Linux hosts still need `TrustedUserCAKeys` pointing at the authority's public key. Nexterm does not change host configuration.

## What is not included yet

- Choosing an authority from the account's groups. The server setting chooses the authority.
- Minting step-ca tokens. The authority stores a token that step-ca already accepts.
- Refreshing a certificate after the session has authenticated. OpenSSH checks the certificate at login.
- SAML group claims. Group mappings read the groups stored for OpenID Connect accounts.
- Signing with a local CA key that is not Ed25519. Vault, step-ca, and webhooks can return other certificate types.
