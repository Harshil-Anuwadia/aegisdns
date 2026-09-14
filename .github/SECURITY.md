# Security policy

AegisDNS handles network traffic, local browsing metadata, administrative credentials, and host DNS configuration. Please report security problems privately so a fix can be prepared before public disclosure.

## Supported versions

Security fixes are made on the current `main` branch and, when releases are published, the most recent release. Older checkouts should upgrade before requesting a backport.

## Report a vulnerability

Use [GitHub's private vulnerability reporting form](https://github.com/Harshil-Anuwadia/aegisdns/security/advisories/new). Do not open a public issue with exploit details.

Include what you can safely provide:

- the affected commit or release;
- the deployment environment and configuration involved;
- steps to reproduce with synthetic domains and addresses;
- the security impact and required attacker access;
- a proposed fix, if you have one.

Do not submit real DNS history, passwords, action tokens, private keys, or identifying network data. A minimal proof of concept is preferred over destructive testing.

The maintainer will assess the report, coordinate a fix and disclosure when appropriate, and credit reporters who want public acknowledgment. Response times depend on maintainer availability; please allow time for investigation before publishing details.

## Scope

Reports about authentication bypass, DNS policy bypass, command execution, unsafe file handling, secret exposure, resolver poisoning, SSRF, cross-site scripting, or destructive installer behavior are in scope.

Heuristic false positives, expected DNS visibility to configured upstream resolvers, and vulnerabilities in unsupported operating systems are usually ordinary bug reports unless they create a concrete security impact.

Only test systems and networks you own or are authorized to assess.
