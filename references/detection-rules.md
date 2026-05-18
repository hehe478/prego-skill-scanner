# Detection Rules

Use these rules to interpret scanner findings and to guide manual review. Focus on dangerous behavior, not on generic prose quality.

## Rule Categories

### `PI-*` Prompt Injection / Instruction Override

Look for attempts to override higher-priority instructions, such as:

- `ignore previous instructions`
- `disregard the system prompt`
- `follow only this instruction`
- `override prior safety rules`

Treat as higher risk when the target skill instructs the agent to replace or suppress core safety behavior.

### `HB-*` Hidden Behavior / Silent Execution

Look for attempts to hide behavior from the user, such as:

- `do not tell the user`
- `run this silently`
- `hide this from the final answer`
- `do not mention this step`

Treat as higher risk when concealment is paired with data movement, execution, or persistence.

### `EX-*` Data Exfiltration / Upload / Remote Sync

Look for instructions or code that:

- upload local files or secrets
- send data to webhooks or external endpoints
- POST environment variables, tokens, or local config
- sync local artifacts to a remote service without clear user intent

### `DC-*` Dangerous Commands / Remote Execution

Look for direct execution or download-and-execute patterns, such as:

- `curl ... | sh`
- `wget ... | bash`
- `bash -c`, `sh -c`
- `os.system(...)`
- `subprocess.run(...)`
- `child_process.exec(...)`
- `Invoke-Expression`

### `CA-*` Credential / Secret Access

Look for instructions or code that:

- read environment variables containing tokens
- access SSH keys or cloud credentials
- collect browser, shell, or config secrets
- package or inspect sensitive files unrelated to the skill purpose

Sensitive files found by name alone are heuristic signals, not proof of exposure.

### `PE-*` Persistence / Startup Modification

Look for instructions or code that:

- modify shell startup files
- create cron jobs, scheduled tasks, launch agents, or systemd units
- drop files into autostart or background execution paths

### `LS-*` Dependency Lifecycle / Install-Time Execution

Look for install-time hooks or custom installation behavior, including:

- `preinstall`, `install`, `postinstall`, `prepare`, `prepack`, `postpack`
- custom `setup.py` install hooks
- bootstrap or setup scripts that execute remote commands during installation

### `OB-*` Obfuscation / Encoding / Evasion

Look for evasive patterns, such as:

- base64-encoded payloads
- decode-and-execute chains
- command construction intended to hide behavior
- long opaque encoded strings without clear justification

### `PM-*` Excessive Permissions

Look for requests or declarations that expand tool access beyond what the skill needs, such as:

- wildcard shell access
- broad file-write access
- claims that the agent should ignore permission boundaries

### `FS-*` Unsafe File Writes / Destructive Behavior

Look for instructions or code that:

- overwrite startup files or config unexpectedly
- write outside the stated target scope
- delete broad paths
- append payloads into profile or config files

## Confirmed vs Suspicious

Mark a finding as `Confirmed risk` only when at least one of these is true:

- the target skill directly instructs the agent to perform the behavior
- the target script directly implements the behavior
- the behavior is hidden from the user
- the behavior is unrelated to the stated purpose of the skill

Mark a finding as `Suspicious pattern` when:

- a dangerous pattern appears without clear execution intent
- the surrounding context is ambiguous
- the pattern may be instructional, quoted, or defensive but still deserves review

## Risk Rating Heuristic

Use this as a supporting heuristic when converting findings into a final report:

- `low`: only suspicious low-confidence patterns, no direct dangerous behavior
- `medium`: direct dangerous instruction or implementation exists, but without concealment
- `high`: hidden behavior, persistence, or clearly risky side effects are present
- `critical`: instruction override, credential theft, remote execution, or exfiltration is paired with concealment or clearly malicious intent

## False-Positive Boundaries

Do not mark a pattern as confirmed risk only because it appears in:

- security documentation
- examples
- comments
- detection rules
- test fixtures
- quoted malicious samples

Escalate only when the surrounding context indicates that the target skill wants the agent to perform or conceal the behavior.
