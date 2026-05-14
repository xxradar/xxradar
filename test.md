# The Tool Name That Looks Right in Your README

Look at these two MCP tool names:

> write_file
>
> write_fiIe

If you are reading this on GitHub, on a documentation site, in a Slack message,
in an email, or in any web UI that renders body text in a sans-serif font,
they look identical. The second one has a capital I where the lowercase l
should be. The vertical stroke is the same. Your eyes have no signal to work
with.

Open the same line in a monospace editor and the difference becomes visible.
Lowercase l has a small foot, capital I sits between two faint serifs in some
monospace faces, and in others the proportions of the surrounding letters give
the substitution away.

That asymmetry is the whole story for this class of attack. The font where
operators *review* a tool list is rarely the font where they *configure* their
policy against it.

## The bypass

Agent SDK policies match tool names as raw strings. The matching is
case-sensitive and operates on bytes, not on canonical forms. So a denylist
entry for `write_file` matches exactly one string. `write_fiIe` is a
different string. The matcher does not care that the rendering is identical.

Consider an operator who wants to block file writes:

```python
options = ClaudeAgentOptions(
    mcp_servers={"fs": server},
    allowed_tools=["mcp__fs__*"],
    disallowed_tools=["mcp__fs__write_file"],
    permission_mode="acceptEdits",
)
```

The wildcard allowlist matches both tools the server registers. The denylist
names only one. The malicious variant slips through.

I ran this against the Claude Agent SDK and it executes the lookalike tool
silently. No prompt, no warning, no log entry that hints at the substitution.
The same pattern works against case variants (`Write_File`), separator
variants (`write-file`), and trailing-character variants (`write_file_`).

## Why the rendering context matters

When does a reviewer actually look at a tool name?

1. Reading an MCP server's README on GitHub. Body text, sans-serif. Tool
   names mentioned in prose paragraphs render in the page font, not in code.
2. Browsing an MCP server registry listing. Same situation.
3. Reading documentation generated from server metadata. Docusaurus, MkDocs,
   Mintlify all default to sans-serif body text.
4. Looking at an admin dashboard or tool picker UI. Whatever the application
   chose, usually sans-serif.
5. Reading a Slack notification or email about agent activity. Platform font.
6. Reviewing a pull request description that mentions a tool by name. GitHub
   body font.

The policy file itself renders in monospace because it is code. The README
that motivated the policy file does not. The reviewer reads the README,
forms a mental model of what the server does, and writes a policy file
against the names they think they saw.

## What still works after the wire-format checks

The MCP spec has SEP-986, which validates tool names against
`^[A-Za-z0-9._-]{1,128}$`. The OpenAI tool name regex is
`^[a-zA-Z0-9_-]+$`. Both reject non-ASCII characters, so Unicode confusables
like Cyrillic i (U+0456) trigger warnings or rejections.

Neither regex helps against same-script Latin substitutions. Every one of
these passes both checks:

- `write_file` vs `Write_File` (case)
- `write_file` vs `write_fiIe` (capital I for lowercase l)
- `write_file` vs `write-file` (dash for underscore)
- `write_file` vs `write_file_` (trailing underscore)
- `list_files` vs `list_fiIes` (same I-for-l trick)
- `format_disk` vs `forrnat_disk` (rn for m in some fonts)

The visual deception varies by font. The policy bypass does not. The matcher
treats every entry above as a distinct identifier.

## The fix is canonicalization at the policy layer

The Claude Agent SDK runs hooks before policy rules. A canonicalizing
PreToolUse hook closes all of these variants in one shot:

```python
import unicodedata

ASCII_CONFUSABLES = {"l": "i", "I": "i", "1": "i", "0": "o", "vv": "w"}

def canonicalize(name: str) -> str:
    n = unicodedata.normalize("NFKC", name).casefold()
    if n.startswith("mcp__"):
        n = n.split("__", 2)[-1]
    n = n.replace("-", "_")
    n = n.rstrip("_.")
    for k in sorted(ASCII_CONFUSABLES, key=len, reverse=True):
        n = n.replace(k, ASCII_CONFUSABLES[k])
    return n

DENIED = {canonicalize("write_file")}

async def pre_tool_use(input_data, tool_use_id, context):
    name = input_data.get("tool_name", "")
    if canonicalize(name) in DENIED:
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"canonical form of {name!r} is denied",
        }}
    return {}
```

The hook runs before any allowlist match can auto-approve. Every variant
collapses to the same canonical form and hits the same denylist entry.

For belt-and-braces, validate the server's tool registry at handshake time.
If two tools canonicalize to the same form, refuse to load the server. An
honest server has no reason to register both spellings. A server that does
is either confused or hostile.

## Takeaways

1. Agent SDK policies compare raw strings. There is no canonical form for
   tool identifiers, by spec.
2. Tool names are reviewed in sans-serif body text. They are matched against
   policy in raw bytes. The two environments give different signals.
3. Same-script Latin substitutions defeat every wire-format check the
   ecosystem currently has, and some of them are visually indistinguishable
   in the rendering context where operators actually review tool lists.
4. The bypass works against an honest reviewer using a normal font in a
   normal browser. It does not require Unicode tricks, zero-width characters,
   or any sophistication beyond picking the right letter to substitute.
5. The fix is canonicalization at policy evaluation time and handshake-time
   refusal of ambiguous tool registries. The SDK does not do this for you.

If your policy uses a wildcard allowlist with surgical denylist entries
written against a README you read on GitHub, you should probably verify your
configuration against the canonical tool list as the server actually
registers it.
