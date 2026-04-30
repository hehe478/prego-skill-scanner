# Scope And Exclusions

This skill is a lightweight, local, static first-pass scanner. Keep the scope narrow and predictable.

## Supported Inputs

- Local skill directories
- Single local files, including `SKILL.md`
- Explicitly provided single files even if their extension is outside the directory-mode allowlist

Single-file mode scans only the provided file. Do not expand the scan to the parent directory.

## Directory-Mode Text Allowlist

- `.md`
- `.txt`
- `.yaml`
- `.yml`
- `.json`
- `.toml`
- `.py`
- `.js`
- `.ts`
- `.mjs`
- `.cjs`
- `.sh`
- `.bash`
- `.zsh`
- `.ps1`

## Special Filenames

Apply install-time or dependency-oriented checks to:

- `package.json`
- `package-lock.json`
- `pyproject.toml`
- `setup.py`
- `setup.cfg`
- `requirements.txt`
- `Pipfile`
- `poetry.lock`
- `pnpm-lock.yaml`
- `yarn.lock`

## Sensitive Files

Treat these as presence-only signals. Do not read or print their contents.

- `.env`
- `.env.*`
- `.npmrc`
- `.pypirc`
- `.netrc`
- `.git-credentials`
- `id_rsa`
- `id_ed25519`
- `known_hosts`
- `authorized_keys`
- `*.pem`
- `*.key`
- `*.p12`
- `*.pfx`
- `.aws/credentials`
- `.aws/config`
- `.config/gcloud/application_default_credentials.json`
- `.docker/config.json`
- `.kube/config`
- `credentials.json`
- `secrets.json`
- `*service-account*.json`

Special case:

- `.env.example`
- `.env.sample`
- `.env.template`

These are suspicious by presence only, default to low confidence, and must not be treated as confirmed credential exposure by filename alone.

## Default Exclusions

Skip these directories by default:

- `.git`
- `node_modules`
- `dist`
- `build`
- `__pycache__`
- `.venv`

Skip these file classes by default:

- binary files
- archive files
- files larger than the configured size limit
- symlinks

## File Size Limit

- Default maximum file size: `512 KiB`
- Configure with `--max-file-kb`
- Do not partially scan oversized files
- Record skipped oversized files in scanner output

## Symlink Policy

- Do not follow symlinks by default
- Record all skipped symlinks
- If a symlink resolves outside the target root, record `symlink_outside_root`

## Archive Policy

- Do not unpack archives by default
- Record archive files as skipped

## Non-Goals

Do not:

- execute target code
- install target dependencies
- fetch URLs from the target unless the user explicitly asks
- unpack archives
- perform dynamic malware analysis
- perform network-based reputation checks
