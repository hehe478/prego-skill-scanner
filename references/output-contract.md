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

## Verdict

Write `Verdict` as one natural-language sentence that directly answers whether the skill appears safe to use cautiously and why.

Example:

- `This skill contains medium-risk suspicious instructions; review its install and bootstrap behavior manually before use.`
- `No dangerous behavior was found in the reviewed material; the skill appears safe to use cautiously based on the inspected files.`

## Risk Rating

Use one of:

- `low`
- `medium`
- `high`
- `critical`

Base the rating on dangerous behavior, concealment, persistence, and the likelihood that the skill would cause harmful side effects if followed.

Reference rubric:

- `low`: only low-confidence suspicious patterns, no direct dangerous instruction or implementation
- `medium`: direct dangerous instruction or implementation is present, but not hidden
- `high`: hidden behavior, persistence, or materially risky behavior is present
- `critical`: safety-override attempts, credential theft, remote execution, or exfiltration are combined with concealment or clearly malicious intent

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

## No-Findings Case

If the review finds no dangerous behavior:

- `Verdict` should explicitly say that no dangerous behavior was found in the reviewed material.
- `Risk rating` should be `low`.
- `Confidence` should be `high`.
- `Confirmed risks` should be empty.
- `Suspicious patterns` should be empty.

Still include any meaningful `Coverage limitations` if the review scope was partial.
