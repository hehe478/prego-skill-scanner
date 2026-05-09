# Output Contract

Before producing the final report, follow this structure.

## Required Sections

1. `Verdict`
2. `Risk rating`
3. `Confirmed risks`
4. `Suspicious patterns`
5. `Evidence`
6. `Recommended fixes`
7. `Coverage limitations`

## Risk Rating

Use one of:

- `low`
- `medium`
- `high`
- `critical`

Base the rating on dangerous behavior, concealment, persistence, and the likelihood that the skill would cause harmful side effects if followed.

## Confidence

Use:

- `low`
- `medium`
- `high`

Confidence reflects evidence quality, not severity.

## Evidence Requirements

For each finding, include:

- `rule_id`
- `category`
- `severity`
- `confidence`
- `path`
- `line`
- `snippet`
- `reason`
- `recommended_fix`

Use repo-relative or target-relative paths by default. Include absolute paths only when the user explicitly asks for local file system locations.

## Secret Redaction

Never echo raw secrets in the report.

- Redact API keys, bearer tokens, cookies, session values, SSH keys, private key material, and cloud credentials.
- If a sensitive file is reported by presence only, use:
  `[sensitive file detected; content suppressed]`

## Coverage Limitations

Always mention meaningful gaps, such as:

- sensitive files not read by design
- files or folders not reviewed because the user only supplied partial content
- areas not inspected because executing or installing the target would violate the safety boundaries

## Reporting Standard

- Prefer high recall for suspicious dangerous-behavior signals.
- Do not label a finding as confirmed unless the target directly instructs or implements the behavior.
- Keep the report concrete and evidence-led.
