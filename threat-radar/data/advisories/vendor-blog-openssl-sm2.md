# Patch Now: Buffer Overflow in OpenSSL SM2 Decryption (CVE-2021-3711)

*Posted by the BlueTeam Labs research team — 2024-03-28*

Last week, our red team disclosed a heap buffer overflow in OpenSSL's SM2
decryption routine, which we've coordinated with the OpenSSL project. The
issue, tracked as **CVE-2021-3711**, affects OpenSSL 1.1.1 through 1.1.1k and
can be triggered by an attacker who can induce an application to decrypt an
attacker-controlled ciphertext using SM2 keys.

## Who's affected

Any application that calls `EVP_PKEY_decrypt` with an SM2 key and does not
size the output buffer against the maximum possible plaintext length. In
practice this shows up in:

- TLS terminators that negotiate GM/T cipher suites (primarily in Asia-Pacific
  deployments)
- VPN appliances that embed OpenSSL 1.1.1k and support SM2 certificate
  authentication
- Any IoT/OT gateway that exposes an SM2-aware management interface

The overflow can yield remote code execution on the server-side process.
CVSS 9.8.

## Mitigation

- Upgrade to OpenSSL 1.1.1l or later.
- If patching is not possible for legacy appliances, disable SM2 cipher
  suites at the network edge and block inbound SM2 certificate negotiation
  at the firewall.

No in-the-wild exploitation has been observed at time of publication, but we
expect proof-of-concept code to surface shortly.
