# York eClass MCP

Connect your own York University eClass account to Codex or another AI client that supports local MCP servers over stdio. This unofficial tool can read your courses, assignments, upcoming calendar events, and announcements. It can save course snapshots and download attachments locally. It does not submit assignments, send messages, or change anything on York's servers.

## Install and sign in

Clone this repository and open a terminal in the checkout. The commands below use Bash on Linux or macOS. Use Python 3.11 or newer.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r mcp_requirements.txt
.venv/bin/python eclass.py login
```

1. Complete Passport York and Duo in the browser.
2. Cancel any prompt to open the Moodle app. If you land on the dashboard, reopen the URL printed by the script.
3. Right-click **Click here to launch the app** and copy the link. Paste it into the terminal’s hidden prompt. Treat that link like a password and keep it out of chat.

Check the connection with `.venv/bin/python eclass.py status`. If York expires your token, run `login` again.

## Connect your AI client

For Codex, run this from the checkout:

```bash
codex mcp add eclass -- "$PWD/.venv/bin/python" "$PWD/eclass_mcp.py"
```

Restart Codex and check `/mcp` in the terminal UI. Try asking “What’s due this week in eClass?” For another local MCP client, set the transport to stdio and use the absolute path to `.venv/bin/python` as the command and the absolute path to `eclass_mcp.py` as its only argument. Live tools need network access to York. A full sync can take longer than some clients’ default tool timeout. In Codex, you can set `tool_timeout_sec = 600` under `[mcp_servers.eclass]` in `~/.codex/config.toml`.

| What you want | Tool |
| --- | --- |
| Verify your login or find a course ID | `check_connection`, `list_courses` |
| Read course sections, assignment instructions, or announcements | `get_course_contents`, `get_assignments`, `get_announcements` |
| See upcoming events | `get_upcoming_events` |
| Refresh the local snapshot, see when it was fetched, or see what changed | `sync_courses`, `get_snapshot_status`, `get_changes` |
| Download an attachment by course ID, module ID, and exact filename | `download_resource` |

The course list, contents, assignments, and upcoming-event tools accept `source="snapshot"` for offline reads after a sync. Check the returned retrieval time before relying on a deadline. The comparison covers course details, sections, assignments, and the upcoming calendar view. Instructors can also post dates only in announcements or attachments, so check those sources when needed.

If your AI client only accepts remote MCP URLs, you can instead run `.venv/bin/python eclass.py sync` and give it just the generated course Markdown you want it to read.

## Local data and tests

The login is stored in `.state/`. Snapshots and downloads go under `eClass/`. Git ignores both directories. Keep them private. To delete your saved local token, use `.venv/bin/python eclass.py forget`. This does not revoke the token on York’s servers.

Run `.venv/bin/python -m unittest -v` to test with synthetic credentials and course data. No York account is needed for the tests.
