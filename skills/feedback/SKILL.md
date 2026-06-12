---
description: Submit feedback for a Secret Protector finding ID.
disable-model-invocation: true
allowed-tools: Bash
---

# Secret Protector Feedback

Submit feedback for finding `$ARGUMENTS`.

Ask the user whether it was:
- false_positive
- true_positive
- unknown

Then run one of:
- `mamoraku-secret feedback $ARGUMENTS --label false_positive`
- `mamoraku-secret feedback $ARGUMENTS --label true_positive`
- `mamoraku-secret feedback $ARGUMENTS --label unknown`

Do not ask for or reveal the secret value.
