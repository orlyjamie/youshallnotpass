"""
youshallnotpass — a configurable pre_tool_call policy gate for Hermes.

Per-tool and per-platform: every tool call gets an action —
  "allow"    run it
  "approve"  STOP for operator approval (Telegram ✅/❌ or CLI), block if denied
  "deny"     hard-block, always

Resolution order for a (tool, platform):
  policy["platforms"][platform][tool]  >  policy["rules"][tool]  >  policy["default"]

Skills run as `terminal` commands (not distinct tools), so they're gated surgically
via `command_patterns` — these are registered with Hermes' native dangerous-command
gate so a matching shell command triggers the same approval UI.

CONFIG: edit  $HERMES_HOME/youshallnotpass.json  (re-read live on change). Example:
  {
    "default": "allow",
    "rules":      { "mail_send": "approve", "web_fetch": "allow", "bash": "approve" },
    "platforms":  { "telegram": { "bash": "deny", "web_fetch": "deny" },
                    "cli":      { "bash": "allow" } },
    "command_patterns": [ ["\\\\bxurl\\\\b.*\\\\bpost\\\\b", "x/twitter post"] ]
  }

Requirements: approvals.mode: manual (never "smart"/"off"); no YOLO; gateway
allowlist set so only YOU answer prompts.

Verified contract: ctx.register_hook("pre_tool_call", cb); hook called with KEYWORD
tool_name=/args=; to block it must return {"action":"block","message":...} (a bare
string is ignored); detection iterates DANGEROUS_PATTERNS_COMPILED on the lowercased
command.
"""

import contextvars
import json
import logging
import os
import re
from pathlib import Path

from tools import approval

logger = logging.getLogger(__name__)

# Platform of the message currently being handled. Hermes only binds
# HERMES_SESSION_PLATFORM *after* slash-command dispatch, so when /ynp runs
# approval._get_session_platform() is still empty. We capture it ourselves from
# the pre_gateway_dispatch hook (fires earlier in the SAME task), via a contextvar
# that propagates to the command handler, plus a module fallback for safety.
_gw_platform: "contextvars.ContextVar[str | None]" = contextvars.ContextVar("ynp_gw_platform", default=None)
_last_platform = {"v": None}


def _capture_platform(event=None, gateway=None, **kwargs):
    """pre_gateway_dispatch hook: record the inbound message's platform so /ynp
    (dispatched before Hermes binds the session env) can resolve it. Never
    influences dispatch."""
    try:
        src = getattr(event, "source", None)
        plat = getattr(src, "platform", None)
        val = getattr(plat, "value", None) or (str(plat) if plat else None)
        if val:
            _gw_platform.set(val)
            _last_platform["v"] = val
    except Exception:
        pass
    return None

_DEFAULT_POLICY = {
    "default": "allow",
    "rules": {
        # hardmail / hardcal already self-gate their writes (richer recipient/subject
        # cards, and fail-safe even if this plugin is off) — set to "allow" so we don't
        # DOUBLE-prompt them.
        "mail_send": "allow",
        "cal_create": "allow",
        "cal_delete": "allow",
        # generic outbound tools with NO built-in gate still require approval:
        "send_email": "approve",
        "send_message": "approve",
        "post_webhook": "approve",
        "social_post": "approve",
    },
    "platforms": {},
    # terminal/skill commands to surface through the native approval gate
    "command_patterns": [
        [r"\bhimalaya\b.*\b(template|message)\s+send\b", "send email (himalaya)"],
        [r"\bhimalaya\b.*\bmessage\s+(reply|forward|delete)\b", "reply/forward/delete email (himalaya)"],
        [r"\bxurl\b.*\b(post|dm|reply|like|repost|follow|block)\b", "x/twitter write (xurl)"],
        [r"\bgh\b\s+(pr\s+merge|pr\s+close|issue\s+comment|issue\s+create|repo\s+delete)\b", "github write (gh)"],
        [r"\bgit\b\s+push\b.*--force", "git force-push"],
    ],
}

# Tools that gate THEMSELVES (their plugin asks before the dangerous write), so the
# default policy leaves them "allow" to avoid a double-prompt. Surfaced in the catalog
# with a 🔒 note so the operator understands they're still protected.
_SELF_GATED = {
    "mail_send": "hardmail asks before sending",
    "cal_create": "hardcal asks before creating",
    "cal_delete": "hardcal asks before deleting",
}

# accept "ask" as a friendly alias for "approve"
_ACTION_ALIASES = {"ask": "approve"}
_VALID_ACTIONS = ("allow", "approve", "deny")


def _norm_action(a: str) -> str:
    a = (a or "").lower()
    return _ACTION_ALIASES.get(a, a)


_STATE_GLYPH = {"allow": "🟢 allow", "approve": "🟡 ask", "deny": "🔴 deny"}

_policy_cache = {"mtime": None, "data": None}


def _config_path() -> Path:
    home = Path(os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes")))
    return home / "youshallnotpass.json"


def _policy() -> dict:
    """Load policy from disk, falling back to built-in defaults. Re-reads when the
    file changes (mtime), so edits take effect without a restart."""
    path = _config_path()
    try:
        mtime = path.stat().st_mtime if path.exists() else None
    except OSError:
        mtime = None
    if _policy_cache["data"] is not None and _policy_cache["mtime"] == mtime:
        return _policy_cache["data"]

    data = dict(_DEFAULT_POLICY)
    if mtime is not None:
        try:
            user = json.loads(path.read_text())
            # shallow merge: user keys win
            merged = dict(_DEFAULT_POLICY)
            merged.update(user)
            # merge rules/platforms maps rather than replacing wholesale
            merged["rules"] = {**_DEFAULT_POLICY["rules"], **(user.get("rules") or {})}
            merged["platforms"] = {**_DEFAULT_POLICY["platforms"], **(user.get("platforms") or {})}
            data = merged
        except Exception as e:
            logger.warning("youshallnotpass: bad config %s (%s) — using defaults", path, e)
    _policy_cache["mtime"] = mtime
    _policy_cache["data"] = data
    return data


def _current_platform() -> str:
    # 1) Hermes' own session env (set during agent.run / tool calls).
    try:
        p = approval._get_session_platform()
        if p:
            return p
    except Exception:
        pass
    # 2) Platform captured by our pre_gateway_dispatch hook (works during slash
    #    dispatch, before Hermes binds the session env). Contextvar first (task-local,
    #    concurrency-safe), then module fallback.
    return _gw_platform.get() or _last_platform["v"] or "default"


def _resolve_action(tool_name: str, platform: str, policy: dict) -> str:
    per_plat = (policy.get("platforms") or {}).get(platform) or {}
    if tool_name in per_plat:
        return per_plat[tool_name]
    rules = policy.get("rules") or {}
    if tool_name in rules:
        return rules[tool_name]
    return policy.get("default", "allow")


def _summarize(args) -> str:
    try:
        s = json.dumps(args, default=str)
    except Exception:
        s = str(args)
    return s[:200]


def _require_approval(summary: str, pattern_key: str = "youshallnotpass") -> bool:
    """Block until the operator approves (Telegram buttons / CLI prompt). FAIL CLOSED.

    Honours the chosen SCOPE so "Session"/"Always" actually stick (keyed per tool):
      "Session" -> approve_session(); "Always" -> approve_permanent() (persisted).
    Short-circuits if `pattern_key` is already session/permanently approved."""
    try:
        session_key = approval.get_current_session_key()
        try:
            if approval.is_approved(session_key, pattern_key):
                return True
        except Exception:
            pass
        notify_cb = getattr(approval, "_gateway_notify_cbs", {}).get(session_key)
        data = {"command": summary, "description": summary, "pattern_key": pattern_key}
        if notify_cb is not None:
            res = approval._await_gateway_decision(session_key, notify_cb, data) or {}
            choice = res.get("choice")
        else:
            choice = approval.prompt_dangerous_approval(summary, summary)
        try:
            if choice == "session":
                approval.approve_session(session_key, pattern_key)
            elif choice == "always":
                approval.approve_permanent(pattern_key)
                try:
                    approval.save_permanent_allowlist(approval._permanent_approved)
                except Exception:
                    pass
        except Exception:
            pass
        return choice in ("once", "session", "always", "approve", "yes", "y")
    except Exception as e:
        logger.warning("youshallnotpass: approval unavailable (%s) — denying", e)
        return False


def _pre_tool_call(tool_name=None, args=None, **kwargs):
    if not tool_name:
        return None
    policy = _policy()
    if policy.get("enabled") is False:   # disarmed via /ynp off
        return None
    platform = _current_platform()
    action = _resolve_action(tool_name, platform, policy)

    if action == "deny":
        return {"action": "block",
                "message": f"youshallnotpass: '{tool_name}' is denied by policy on '{platform}'."}
    if action == "approve":
        if not _require_approval(f"{tool_name} {_summarize(args)}", pattern_key=f"ynp:{tool_name}"):
            return {"action": "block",
                    "message": f"youshallnotpass: '{tool_name}' was not approved by the operator."}
    return None  # allow


def _register_command_patterns(policy: dict) -> None:
    """Register terminal/skill command patterns with the native dangerous-command gate
    so matching shell commands trigger the same approval UI."""
    for entry in policy.get("command_patterns") or []:
        try:
            pattern, desc = entry[0], entry[1]
        except (IndexError, TypeError):
            continue
        try:
            if hasattr(approval, "register_dangerous_pattern"):
                approval.register_dangerous_pattern(pattern, desc)
            else:
                approval.DANGEROUS_PATTERNS.append((pattern, desc))
                approval.DANGEROUS_PATTERNS_COMPILED.append((re.compile(pattern, approval._RE_FLAGS), desc))
        except Exception as e:
            logger.warning("youshallnotpass: could not register pattern %r (%s)", pattern, e)


# --------------------------------------------------------------------------- #
# /ynp slash command — OPERATOR-ONLY live policy editing (chat: dashboard + Telegram)
#
# Slash commands are typed by the human operator, never callable by the model, so
# an injected email can't loosen or disarm the gate. (Restrict who may run it with
# Hermes' slash-access allowlist if your gateway has multiple users.)
# --------------------------------------------------------------------------- #
def _load_raw() -> dict:
    path = _config_path()
    if path.exists():
        try:
            return json.loads(path.read_text())
        except Exception:
            return {}
    return {}


def _save_raw(raw: dict) -> None:
    path = _config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(raw, indent=2))
    _policy_cache["mtime"] = None  # force reload on next tool call


def _render_policy() -> str:
    p = _policy()
    armed = p.get("enabled") is not False
    lines = [f"youshallnotpass — {'ARMED ✅' if armed else 'DISARMED ⚠️ (all tools allowed)'}",
             f"default: {p.get('default', 'allow')}", "rules:"]
    for tool, act in sorted((p.get("rules") or {}).items()):
        lines.append(f"  {tool}: {act}")
    plats = p.get("platforms") or {}
    if plats:
        lines.append("platforms:")
        for plat, rules in plats.items():
            lines.append(f"  {plat}: " + ", ".join(f"{t}={a}" for t, a in rules.items()))
    return "\n".join(lines)


def _platform_tool_scope(platform: str):
    """Return the SET of tool names actually enabled on `platform` — i.e. the
    capability cap from `platform_toolsets`, expanded through Hermes' own toolset
    resolver (handles composite/plugin `hermes-<platform>` toolsets). Returns None
    if it can't be determined, in which case the catalog falls back to the full
    registry. This is what makes `/ynp list` on Telegram show ONLY Telegram's tools."""
    try:
        try:
            from hermes_cli.config import load_config
            cfg = load_config() or {}
        except Exception:
            import yaml
            home = Path(os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes")))
            cfg = yaml.safe_load((home / "config.yaml").read_text()) or {}

        pts = cfg.get("platform_toolsets") or {}
        names = pts.get(platform)
        if not isinstance(names, list) or not names:
            names = [f"hermes-{platform}"]   # Hermes' default toolset for the platform
        names = [str(n) for n in names]

        # Each name may be a built-in/composite toolset (resolved via toolsets) OR a
        # plugin toolset like `hardmail` (only known to the live registry). Union both.
        from toolsets import resolve_toolset
        from tools.registry import registry
        tools = set()
        for name in names:
            resolved = resolve_toolset(name)            # built-in / composite / hermes-*
            if resolved:
                tools.update(resolved)
            else:
                tools.update(registry.get_tool_names_for_toolset(name))  # plugin toolset
        return tools   # may be empty (genuinely capped to nothing) — that's a real answer
    except Exception as e:
        logger.debug("youshallnotpass: platform scope unavailable for %r (%s)", platform, e)
        return None


def _catalog_view() -> str:
    """Tool catalog scoped to what's ACTUALLY enabled on the current platform.

    On Telegram this shows only the tools in `platform_toolsets[telegram]` (the cap),
    each with its resolved youshallnotpass state. Reuses Hermes' registry + toolset
    resolver — we don't keep our own list. Falls back to the raw-policy view if the
    registry isn't importable."""
    try:
        from tools.registry import registry
        tool_to_toolset = registry.get_tool_to_toolset_map()
    except Exception as e:
        logger.debug("youshallnotpass: registry unavailable for catalog (%s)", e)
        return _render_policy()

    if not tool_to_toolset:
        return _render_policy()

    p = _policy()
    armed = p.get("enabled") is not False
    platform = _current_platform()

    # Scope to the capability cap: only tools enabled on THIS platform.
    scope = _platform_tool_scope(platform)
    if scope is not None:
        visible = {t: ts for t, ts in tool_to_toolset.items() if t in scope}
        hidden_count = len(tool_to_toolset) - len(visible)
    else:
        visible = dict(tool_to_toolset)
        hidden_count = 0

    head = (f"🛡 youshallnotpass · {'ARMED' if armed else 'DISARMED ⚠️ (all tools allowed)'}"
            f" · platform: {platform}")
    lines = [head]
    if scope is not None:
        lines.append(f"  enabled on {platform}: {len(visible)} tool(s)"
                     + (f" · {hidden_count} more exist but are capped off this surface" if hidden_count else ""))
    else:
        lines.append("  (couldn't read platform_toolsets — showing full registry)")
    lines.append("")

    if not visible:
        lines.append(f"  No tools are enabled on {platform}.")
        lines.append("  Add toolsets with `hermes tools`.")
        return "\n".join(lines)

    # group tools by toolset for a readable catalog
    by_toolset: dict = {}
    for tool, toolset in visible.items():
        by_toolset.setdefault(toolset or "·", []).append(tool)

    width = max((len(t) for t in visible), default=12)
    for toolset in sorted(by_toolset):
        lines.append(f"  {toolset}")
        for tool in sorted(by_toolset[toolset]):
            action = _norm_action(_resolve_action(tool, platform, p))
            state = _STATE_GLYPH.get(action, action)
            row = f"    {tool.ljust(width)}  {state}"
            if tool in _SELF_GATED:
                row += f" 🔒 ({_SELF_GATED[tool]})"
            lines.append(row)
        lines.append("")

    lines.append(f"default: {p.get('default', 'allow')}")
    lines.append("Toggle:  /ynp deny|allow|ask <tool> [platform]   (🔒 = plugin self-gates)")
    return "\n".join(lines)


_YNP_HELP = (
    "youshallnotpass policy:\n"
    "  /ynp list                       full live tool catalog + current state\n"
    "  /ynp config                     raw policy (rules / platforms)\n"
    "  /ynp set <tool> <allow|ask|deny> [platform]\n"
    "  /ynp allow|ask|deny <tool> [platform]\n"
    "  /ynp on        (arm)        /ynp off   (disarm)\n"
    "  /ynp reload\n"
    "Actions: allow=run · ask=approve first · deny=block. "
    "Omit platform to apply everywhere. (Remove tools entirely with `hermes tools`.)"
)


def _slash_ynp(raw_args: str):
    parts = (raw_args or "").split()
    if not parts or parts[0].lower() in ("list", "catalog", "tools"):
        return _catalog_view()
    cmd = parts[0].lower()

    if cmd in ("config", "policy", "rules"):
        return _render_policy()

    if cmd in ("on", "off"):
        raw = _load_raw()
        raw["enabled"] = (cmd == "on")
        _save_raw(raw)
        return "youshallnotpass is now " + ("ARMED ✅" if cmd == "on"
                                            else "DISARMED ⚠️ (all tools allowed)")
    if cmd == "reload":
        _policy_cache["mtime"] = None
        return f"Reloaded policy from {_config_path()}"

    if cmd == "set" and len(parts) >= 3:
        tool, action = parts[1], _norm_action(parts[2])
        platform = parts[3] if len(parts) >= 4 else None
    elif cmd in ("allow", "approve", "ask", "deny") and len(parts) >= 2:
        action, tool = _norm_action(cmd), parts[1]
        platform = parts[2] if len(parts) >= 3 else None
    else:
        return _YNP_HELP

    if action not in _VALID_ACTIONS:
        return f"Unknown action '{action}'. Use allow | ask | deny."

    raw = _load_raw()
    if platform:
        raw.setdefault("platforms", {}).setdefault(platform, {})[tool] = action
        scope = f"on {platform}"
    else:
        raw.setdefault("rules", {})[tool] = action
        scope = "everywhere"
    _save_raw(raw)
    return f"✅ {tool} → {action} {scope}"


def register(ctx) -> None:
    _register_command_patterns(_policy())               # surgical terminal/skill gating
    ctx.register_hook("pre_tool_call", _pre_tool_call)   # per-tool / per-platform gate
    ctx.register_hook("pre_gateway_dispatch", _capture_platform)  # learn the platform for /ynp
    ctx.register_command(
        "ynp", _slash_ynp,
        description="Manage the youshallnotpass tool-policy gate (operator-only)",
        args_hint="list | config | allow|ask|deny <tool> [platform] | on | off",
    )
    logger.info("youshallnotpass active — policy at %s", _config_path())
