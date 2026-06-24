# Security Policy

## Reporting a vulnerability

Do not publish credentials, tokens, customer information, or exploit details in a public issue.

Report suspected vulnerabilities privately through the repository owner's GitHub profile or GitHub's private vulnerability reporting feature when available. Include the affected version, reproduction steps, expected behavior, observed behavior, and any relevant logs with secrets removed.

## Credential handling

This repository intentionally contains no default password. Users are responsible for supplying credentials through a secure prompt, a `SecureString`, or a protected RMM secret mapped to the process environment.

Never commit real credentials, `.env` files, exported credential objects, or customer-specific configuration to the repository.

## Operational recommendation

For production fleets, Windows LAPS or another per-device credential-rotation system is strongly preferred over a shared local administrator password.
