---
description: Temporarily pause or resume Secret Protector detection for the current session.
disable-model-invocation: true
allowed-tools: Bash
---

# Secret Protector Pause / Resume

Use this when the user wants to temporarily stop secret detection.

## Pause (current session)

```bash
mamoraku-secret pause --session-key $SESSION_KEY
```

To pause for a limited time (e.g. 30 minutes):

```bash
mamoraku-secret pause --session-key $SESSION_KEY --duration 1800
```

If `$ARGUMENTS` was provided by the user, use it as the session key.
If no session key is available, omit `--session-key` to pause globally.

## Resume (current session)

```bash
mamoraku-secret resume --session-key $SESSION_KEY
```

Or resume globally:

```bash
mamoraku-secret resume --global
```

## Check pause state

```bash
mamoraku-secret status
```

## Notes
- Pausing skips all secret scanning (regex + entropy + reranker).
- Existing whitelists and session allows are unaffected.
- `--duration` auto-resumes after the specified seconds; omitting it requires a manual `resume`.
- Use `--global` to pause/resume across all sessions at once.
