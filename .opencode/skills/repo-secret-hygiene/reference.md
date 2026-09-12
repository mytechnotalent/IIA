# Repo Secret Hygiene — Reference

## Detection patterns

Hard findings (always fail):

| Name | What it catches |
| --- | --- |
| `private-key` | PEM private key headers (RSA/EC/DSA/OpenSSH/PGP) |
| `aws-access-key` | `AKIA…` access key ids |
| `github-token` | `ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` tokens |
| `slack-token` | `xox[baprs]-…` tokens |
| `google-api-key` | `AIza…` keys |
| `jwt` | three-part base64url JWTs |
| `bearer-token` | `Authorization: Bearer <token>` |
| `generic-secret` | `api_key`/`secret`/`token`/`password`/`passphrase` assigned a quoted value >= 12 chars |

Soft findings (fail only with `--strict`): `private-ipv4`, `mac-address`,
`user-path`, `email`.

## Allowlist policy

A line is skipped when it contains a placeholder token (`<secret>`,
`changeme`, `example`, `redacted`, `dummy`, `fake`, `xxxx`, `deadbeef`,
`0000000000`, …). Specific placeholder addresses are permitted in code:
`192.168.1.1`, `192.168.1.50`, `10.0.0.1/3/5`, `127.0.0.1`, and MACs
`00:11:22:33:44:55`, `aa:bb:cc:dd:ee:ff`, plus all-zero/all-ff. Email
domains `example.com/org/net` and `test.com` are permitted.

To add an exception, prefer changing the example to a documented
placeholder over widening the allowlist. If a real value must appear,
store it in a password manager, not the repo.

## Modes

```bash
python3 .opencode/skills/repo-secret-hygiene/scan_secrets.py --tree
python3 .opencode/skills/repo-secret-hygiene/scan_secrets.py --staged
python3 .opencode/skills/repo-secret-hygiene/scan_secrets.py --history
python3 .opencode/skills/repo-secret-hygiene/scan_secrets.py --strict
```

Exit codes: `0` clean, `1` hard findings, `2` soft findings under `--strict`.

## Pre-commit installation

```bash
cp .opencode/skills/repo-secret-hygiene/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The hook scans the staging area and refuses the commit on any hard finding.

## Incident playbook

1. **Rotate the credential first.** Purge only after the value is dead.
2. Untrack the file and add its path/class to `.gitignore`.
3. Purge history and force-push if a remote exists (`git filter-repo
   --invert-paths --path <file>` then `git push --force-with-lease`).
4. If the repo is public, make it private and request object removal from
   the host; assume forks and caches retain copies.
5. Verify: old value rejected, new value works, and the scanner is clean on
   tree, staged, and history.
6. Record the incident below with the value redacted.

## Incident log

| Date | Scope | Action | Result |
| --- | --- | --- | --- |
| 2026-09-12 | Public repo tracked a live C2 token and device inventory in a skill file | Rotated C2 token and dashboard password; untracked and gitignored the skill; genericized real IP/MAC; squashed history; deleted the public repo | Old token rejected, new credentials verified |
