# Examples

This directory contains static sample skills for demonstrating and testing the Prego Skill Scanner.

These samples are intentionally simplified. Some are benign and should produce no dangerous-behavior findings. Others are malicious or obfuscated and are meant to trigger specific review rules during manual inspection.

## Warning

Do not install, execute, or trust these samples.

- They are test fixtures for review only.
- Any dangerous command or endpoint is illustrative and uses placeholders such as `http://example.com` or `http://placeholder.local`.
- They must never be connected to real credentials, real systems, or real installation workflows.

## How To Use

1. Choose one sample directory.
2. Inspect its `SKILL.md` first.
3. Inspect any adjacent files such as `scripts/`, `package.json`, `tools/`, or `README.md`.
4. Apply the rules from `references/detection-rules.md`.
5. Produce a report using `references/output-contract.md`.

## Sample Matrix

| Sample | Type | Target rules | Expected outcome | Why it exists |
| --- | --- | --- | --- | --- |
| `benign/hello-world` | benign | none | no dangerous behavior | Minimal safe skill |
| `benign/simple-translator` | benign | none | no dangerous behavior | Safe skill with a harmless reference file |
| `malicious/credential-stealer` | malicious | `CA-*`, `EX-*` | confirmed risks | Reads local secrets and prepares to send them out |
| `malicious/hidden-exfil` | malicious | `EX-*`, `HB-*`, `LS-*` | confirmed risks | Hides exfiltration inside install-time behavior |
| `malicious/persistence-attack` | malicious | `PE-*`, `FS-*` | confirmed risks | Persists changes to shell startup or cron |
| `malicious/instruction-override` | malicious | `PI-*`, `HB-*` | confirmed risks | Explicitly overrides higher-priority instructions |
| `obfuscated/base64-payload` | obfuscated | `OB-*` | suspicious patterns | Demonstrates encoding and decode-and-run intent |
| `obfuscated/fake-readme-rce` | obfuscated | `OB-*`, `DC-*` | suspicious patterns or confirmed risks depending on reading depth | Demonstrates risky content hidden inside long documentation |

## Notes For Review

- Benign samples are designed to stay near zero findings.
- Malicious samples should make the dangerous intent visible without containing real malware.
- Obfuscated samples are designed to demonstrate review difficulty and coverage limitations.
- Explanations live only in this README so that the sample files themselves still resemble ordinary skill artifacts.
