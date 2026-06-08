# youshallnotpass

A configurable **per-tool, per-platform policy gate** for the [Hermes](https://github.com/NousResearch/Hermes) agent. Turns a successful prompt-injection from a silent action into a **visible, vetoable approval** — or blocks it outright.

## The idea

Most prompt-injection defences lower the *probability* that an injection succeeds. Far fewer lower the *impact* when it works anyway. youshallnotpass is an impact reducer: it assumes the model can be fooled and decides, per tool and per surface, what a fooled agent is allowed to do.

For every tool call it resolves one action:

```
resolution order:  platforms[platform][tool]  >  rules[tool]  >  default

  allow    run it
  ask      stop for operator approval (Telegram ✅/❌, CLI, or dashboard); fail closed
  deny     hard-block, always
```

This is **additive to Hermes' built-in approval**, which is shell-command/pattern based. That base gate can't reason about a native tool like `web_fetch` (which takes a URL argument, not a shell string). youshallnotpass gates on the **tool identity itself**, so you can say "`web_fetch` requires approval on Telegram but runs freely on the CLI" — something the pattern gate has no vocabulary for.

> The real wall is still the capability cap (`platform_toolsets`): a tool the agent doesn't hold can't be abused. youshallnotpass is the backup for the capabilities you *do* keep.

## Manage it live from chat: `/ynp`

`/ynp` is **operator-typed and never model-callable**, so an injected email cannot loosen or disarm the gate.

```
/ynp list                       tool catalog SCOPED to the current platform + each tool's state
/ynp config                     raw policy (rules / platforms)
/ynp allow|ask|deny <tool> [platform]
/ynp set <tool> <allow|ask|deny> [platform]
/ynp on            (arm)        /ynp off   (disarm)
/ynp reload
```

`/ynp list` reads Hermes' **live tool registry** and the platform's `platform_toolsets`, so it shows only the tools actually enabled on the surface you're typing from:

```
🛡 youshallnotpass · ARMED · platform: telegram
  enabled on telegram: 8 tool(s) · 64 more exist but are capped off this surface

  hardcal
    cal_create           🟢 allow 🔒 (hardcal asks before creating)
    cal_delete           🟢 allow 🔒 (hardcal asks before deleting)
    cal_freebusy         🟢 allow
    cal_list             🟢 allow
  hardmail
    mail_get             🟢 allow
    mail_get_attachment  🟢 allow
    mail_search          🟢 allow
    mail_send            🟢 allow 🔒 (hardmail asks before sending)

default: allow
Toggle:  /ynp deny|allow|ask <tool> [platform]   (🔒 = plugin self-gates)
```

The `🔒` marker flags tools that **self-gate** (their own plugin asks before the dangerous write, e.g. hardmail/hardcal). Those default to `allow` here to avoid a double prompt — the lock keeps that honest. To remove a tool entirely (rather than gate it), use Hermes' own `hermes tools`.

## Install

```bash
mkdir -p "$HERMES_HOME/plugins"
cp -r youshallnotpass "$HERMES_HOME/plugins/youshallnotpass"
```

Enable it and set a manual approval mode in `$HERMES_HOME/config.yaml`:

```yaml
plugins:
  enabled:
    - youshallnotpass

approvals:
  mode: manual        # REQUIRED. Never "smart" (auto-approves) or "off".
  cron_mode: deny
```

Policy is read from `$HERMES_HOME/youshallnotpass.json` (hot-reloaded on change) and is also fully editable via `/ynp`. Example:

```json
{
  "default": "allow",
  "rules":     { "send_email": "ask", "post_webhook": "ask" },
  "platforms": { "telegram": { "terminal": "deny", "web_fetch": "ask" } }
}
```

## Hard requirements (or it silently won't protect you)

- `approvals.mode: manual` — `smart` lets an auxiliary LLM auto-approve (an injection can read as "low-risk"); `off`/YOLO bypass everything.
- No `HERMES_YOLO_MODE` / `--yolo` / `/yolo`.
- Gateway **pairing/allowlist** configured, so only *your* account receives and answers approval prompts (the adapter fail-closes to deny).
- Not running under a sandbox executor that bypasses the dangerous-command layer.

## Where you see the approval

- **Gateway (Telegram/Discord/…):** an inline keyboard; the agent blocks until you tap.
- **CLI:** the same gate as a terminal prompt.

It reuses Hermes' own approval flow (`tools/approval.py`); the plugin just adds per-tool/per-platform resolution on top.

## Notes

- **Stdlib only** — no third-party dependencies.
- Optional command-pattern gating for skill/terminal commands degrades gracefully if the host lacks a public `register_dangerous_pattern` hook (it falls back to extending the compiled pattern list, which could break on an upstream rename).
- Operator-only `/ynp`: arm/disarm and policy edits are never reachable by the model.

## Pairs well with

- **[hardmail](../hardmail)** / **[hardcal](../hardcal)** — native, shell-free email & calendar that self-gate their writes.

## License

MIT © 2026 Jamieson O'Reilly (theonejvo)
