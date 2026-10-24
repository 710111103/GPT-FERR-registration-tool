# Security and privacy

Do not commit credentials or runtime data. Keep secrets in local environment variables or an untracked `.env` copied from `.env.example`.

The following must stay out of Git: account databases, access/refresh tokens, cookies, email pools, proxy credentials, API keys, private keys, packet captures, browser profiles, screenshots, logs, and verification artifacts.

Before opening a pull request, review `git diff --cached` and run a secret scanner against the staged tree. If a secret is committed, revoke/rotate it first; deleting it in a later commit is not sufficient.
