---
name: repo-secret-hygiene
description: >
  Mandatory secret and sensitive-data hygiene for the IIA repository and any
  owned repo. Use BEFORE every git commit, push, tag, or repo creation; when
  adding or editing .opencode skills, Markdown docs, config, CI, or test
  fixtures; when handling credentials, tokens, device inventories, PCAPs,
  firmware dumps, or audit reports; and when a secret may have leaked (rotate
  first, then purge). This skill exists because a public repo once shipped a
  live C2 token and network inventory in a tracked skill file.
---

# Repo Secret Hygiene

Hard rule: **no secret, credential, or identifying operational data ever
enters Git.** Assume every tracked byte will one day be public and mirrored,
and that deletion is never sufficient.

## 1. Never track these (any repo)

- Credentials: passwords, API keys, C2 tokens, session tokens, JWTs, private
  keys, `KEEPASS` exports, `.env`, `.netrc`, `.npmrc` with tokens.
- Operational secrets: router/agent tokens, dashboard passwords, Wi-Fi
  passphrases, SNMP communities, `authorized_keys`.
- Identifying inventory: real private IPs, real MAC addresses, real SSIDs,
  hostnames, device names, DHCP leases, ARP tables, `/etc/shadow` hashes.
- Capture artifacts: PCAPs, firmware dumps, `reports/` output, screen
  transcripts, crash logs, `.DS_Store`.
- Anything under a local-only skill that documents live infrastructure.

## 2. Tracked vs local-only

- `.opencode/skills/**` is **code** only if it contains no secrets, no live
  inventory, and no credentials. Operational runbooks belong in a
  **gitignored** skill directory (`iot-blue-team-audit/` is ignored).
- Put every credential in a password manager or environment variable, never
  in a file the repo can see.
- Reports, captures, and dumps live under gitignored paths (`reports/`,
  `*.pcap`, `*.bin`, `*.img`).

## 3. Placeholder conventions (use these in docs/tests)

- IPv4: `192.168.1.50`, `10.0.0.5`, `192.168.1.1` (generic gateway).
- MAC: `00:11:22:33:44:55` (globally unique) or `aa:bb:cc:dd:ee:ff`.
- Secrets in examples: `<secret>`, `<token>`, `changeme`, `example`.
- Paths: `/path/to/...` — never a real user's home directory.

## 4. Required sequence before any commit or push

1. Run the scanner on the working tree: `python3
   .opencode/skills/repo-secret-hygiene/scan_secrets.py --tree`.
2. Run it on the staging area: add `--staged`.
3. Run it on history when a remote already exists: add `--history`.
4. Inspect `git status` and `git diff --cached`; confirm only intended files.
5. Confirm `.gitignore` covers skills with operational knowledge.
6. Confirm no remote points anywhere unexpected: `git remote -v`.
7. Only then commit. Never use `-A` blindly; stage explicit paths.

## 5. Never do these

- Do not paste secrets into chat, logs, command output, or error messages.
  Redact to a short prefix with no real characters if a value must be
  referenced.
- Do not `git add -A` in a directory that may hold captures or reports.
- Do not commit a "temporary" token "just for now".
- Do not rely on a force-push to un-leak a secret — old commits stay
  reachable by SHA and in mirrors until garbage collection.
- Do not copy third-party code and strip its license notice.

## 6. If a secret is leaked — order matters

1. **Rotate the credential immediately.** Assume it is compromised. Purging
   history is worthless until the value is dead.
2. Remove the file from tracking and add it to `.gitignore`.
3. Purge history (`git filter-repo`) and force-push if a remote exists.
4. If public: request removal from the host and make the repo private.
5. Verify the old value is rejected and the new value works.
6. Record the incident in `reference.md` without the secret value.

## 7. Automated guardrails in this repo

- `scan_secrets.py` — tree, staged, and history scanner (exit 1 on hard
  findings). Run it in pre-commit and CI.
- `pre-commit` — hook that blocks commits containing hard findings.
- `tests/test_repo_secret_hygiene.py` — fails the test suite if tracked
  files contain hard findings or forbidden path classes.
- `.gitignore` — blocks credential and capture file classes.

See `reference.md` for the detection patterns, allowlist policy, and the
full incident playbook.
