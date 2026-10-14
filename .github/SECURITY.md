# Security

ByteLocker is a public beta with no independent cryptographic audit. Use test credentials while evaluating it.

## Report a vulnerability privately

Contact the repository owner through an already agreed private channel. Use GitHub private vulnerability reporting if enabled. Do not post exploitable details in public issues. No bounty or guaranteed response time is currently offered.

Include affected versions, reproducible steps with synthetic data and observed impact. Never send passwords, keys, tokens, invitations, vaults, backups, databases or Gmail credentials. Redact personal addresses and account identifiers.

## If a secret leaks

Revoke and replace it. Deleting the current file does not remove it from history or downloaded packages. Assess affected sessions and operational keys separately; preserve account data and a verified recovery path.

## Trust boundaries

The server stores encrypted vaults and account metadata; it does not receive Master Passwords or vault keys. An unlocked compromised client can expose its contents. A private URL does not replace authentication or authorization. Backups contain operational secrets and require protected storage.

[Protocol](../docs/crypto-protocol.md) · [Threat model](../docs/threat-model.md) · [Android security](../docs/android-security.md) — detailed technical notes currently in Italian.
