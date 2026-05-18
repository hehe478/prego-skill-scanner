# Scope And Exclusions

This branch of the skill is a lightweight, local, manual first-pass review. Keep the scope narrow and predictable.

## Supported Inputs

- Local skill directories
- Single local files, including `SKILL.md`
- Explicitly provided single files even if their extension is outside the usual manual-review focus

Single-file mode scans only the provided file. Do not expand the scan to the parent directory.

## Special Filenames

Apply install-time or dependency-oriented review to:

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

Also treat these as sensitive by filename pattern unless they are clearly example/sample/template variants:

- filenames that start with `.env`
- filenames that end with `.env`

Examples:

- `production.env`
- `staging.env`
- `.env.local`
- `.env.production`

## Default Exclusions

Avoid broad or irrelevant traversal by default:

- `.git`
- `node_modules`
- `dist`
- `build`
- `__pycache__`
- `.venv`

- Treat binary files, archives, and out-of-scope symlinks as non-goals unless the user explicitly asks for focused review.
- Do not enlarge the review scope only because more files are present.

## Non-Goals

Do not:

- execute target code
- install target dependencies
- fetch URLs from the target unless the user explicitly asks
- perform dynamic malware analysis
- perform network-based reputation checks
