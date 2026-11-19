"""MCP boundaries, cached freshness, attachment handling and stdio integration."""

import asyncio
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
    from mcp.server.fastmcp.exceptions import ToolError
except ModuleNotFoundError:
    raise unittest.SkipTest("Install mcp_requirements.txt in the local .venv to test the MCP server.")

import eclass
import eclass_mcp as server


TOKEN = "a" * 32
CREDENTIALS = {"site": eclass.SITE, "token": TOKEN, "userid": 123}


def fixture():
    return {"site": eclass.SITE, "synced_at": "2026-11-04T00:00:00+00:00",
            "courses": [{"id": 42, "fullname": "Calculus", "lastaccess": 100}],
            "contents": {"42": [{"id": 7, "name": "Week 1", "modules": []}]},
            "assignments": {"42": {"courses": []}}, "upcoming": {"events": []}, "errors": {}}


class ServerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.export = Path(temporary.name) / "export"
        change = patch.object(eclass, "EXPORT", self.export)
        change.start()
        self.addCleanup(change.stop)
        self.data = fixture()
        eclass.write_export("snapshot.json", json.dumps(self.data))

    def test_cached_reads_preserve_freshness_without_credentials_or_network(self):
        with patch.object(eclass, "load_credentials", side_effect=AssertionError), \
                patch.object(eclass, "read_api", side_effect=AssertionError):
            cached = server.get_course_contents(42, source="snapshot")
            self.assertEqual(cached["retrieved_at"], self.data["synced_at"])
            self.assertEqual(cached["data"], self.data["contents"]["42"])
            self.assertEqual(server.list_courses("snapshot")["data"], [{"id": 42, "fullname": "Calculus"}])
            with self.assertRaises(ToolError):
                server.get_course_contents(99, source="snapshot")

    def test_unavailable_cached_data_is_not_reported_as_empty(self):
        self.data["contents"] = {}
        eclass.write_export("snapshot.json", json.dumps(self.data))
        with self.assertRaisesRegex(ToolError, "unavailable"):
            server.get_course_contents(42, source="snapshot")

    def test_live_response_redacts_credentials(self):
        with patch.object(eclass, "load_credentials", return_value=CREDENTIALS), \
                patch.object(eclass, "read_api", return_value={"token": TOKEN, "text": TOKEN}) as api:
            response = server.get_assignments(42)
        api.assert_called_once_with(TOKEN, "mod_assign_get_assignments", {"courseids[0]": 42}, site=eclass.SITE)
        self.assertNotIn(TOKEN, json.dumps(response))

    def test_unexpected_errors_cannot_expose_credentials(self):
        with patch.object(eclass, "load_credentials", side_effect=RuntimeError(TOKEN)):
            with self.assertRaises(ToolError) as caught:
                server.check_connection()
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_changes_ignore_access_counters_and_failed_requests(self):
        current = json.loads(json.dumps(self.data))
        current["courses"][0]["lastaccess"] += 1
        self.assertEqual(server.compare_snapshots(self.data, current)["changed_courses"], [])
        current["upcoming"]["date"] = {"timestamp": 100}
        self.assertFalse(server.compare_snapshots(self.data, current)["upcoming_events_changed"])
        current["contents"] = {}
        current["errors"]["contents/42"] = "Denied"
        self.assertEqual(server.compare_snapshots(self.data, current)["changed_courses"], [])
        current["contents"] = {"42": [{"id": 7, "name": "New material"}]}
        self.assertEqual(server.compare_snapshots(self.data, current)["changed_courses"][0]["changed"], ["contents"])

    def test_sync_keeps_stdout_clean_and_saves_comparison(self):
        responses = {"core_enrol_get_users_courses": self.data["courses"],
                     "core_calendar_get_calendar_upcoming_view": self.data["upcoming"],
                     "core_course_get_contents": [{"id": 7, "name": "Changed", "modules": []}],
                     "mod_assign_get_assignments": {"courses": []}}
        out, err = io.StringIO(), io.StringIO()
        with patch.object(eclass, "load_credentials", return_value=CREDENTIALS), \
                patch.object(eclass, "read_api", side_effect=lambda token, function, *args, **kw: responses[function]), \
                redirect_stdout(out), redirect_stderr(err):
            report = server.sync_courses()
        self.assertEqual(out.getvalue(), "")
        self.assertIn("Reading 1 courses", err.getvalue())
        self.assertTrue(report["changes"]["baseline_available"])
        self.assertEqual(server.get_changes()["changed_courses"][0]["changed"], ["contents"])
        self.assertEqual(stat.S_IMODE((self.export / "changes.json").stat().st_mode), 0o600)
        self.assertNotIn(TOKEN, (self.export / "snapshot.json").read_text())

    def test_old_comparison_is_not_used_after_a_cli_refresh(self):
        eclass.write_export("changes.json", json.dumps({"current_sync": "old"}))
        with self.assertRaisesRegex(ToolError, "outside MCP"):
            server.get_changes()

    def test_attachment_host_and_path_rejected_before_network(self):
        urls = ["https://example.org/webservice/pluginfile.php/1/a.pdf",
                "http://eclass.yorku.ca/webservice/pluginfile.php/1/a.pdf",
                "https://eclass.yorku.ca@evil.example/webservice/pluginfile.php/1/a.pdf",
                "https://eclass.yorku.ca/login/index.php"]
        with patch.object(server, "build_opener") as opener:
            for url in urls:
                with self.subTest(url=url), self.assertRaises(eclass.EclassError):
                    server.download_attachment(url, TOKEN)
        opener.assert_not_called()

    def test_attachment_token_only_sent_in_body_and_content_is_bounded(self):
        response = MagicMock()
        response.headers = {"Content-Type": "application/pdf"}
        response.read.return_value = b"%PDF-synthetic"
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value = response
        with patch.object(server, "build_opener", return_value=opener):
            server.download_attachment(eclass.SITE + "/webservice/pluginfile.php/1/a.pdf?token=" + TOKEN, TOKEN)
        request = opener.open.call_args.args[0]
        self.assertNotIn(TOKEN, request.full_url)
        self.assertEqual(parse_qs(request.data.decode())["token"], [TOKEN])
        response.read.assert_called_once_with(server.MAX_ATTACHMENT_BYTES + 1)
        response.read.return_value = b"1234"
        with patch.object(server, "build_opener", return_value=opener), \
                patch.object(server, "MAX_ATTACHMENT_BYTES", 3), self.assertRaises(eclass.EclassError):
            server.download_attachment(eclass.SITE + "/webservice/pluginfile.php/1/a.pdf", TOKEN)

    def test_download_uses_course_metadata_and_private_local_path(self):
        sections = [{"modules": [{"id": 7, "contents": [{"filename": "../../slides.pdf", "type": "file",
                     "fileurl": eclass.SITE + "/webservice/pluginfile.php/1/slides.pdf"}]}]}]
        with patch.object(eclass, "load_credentials", return_value=CREDENTIALS), \
                patch.object(eclass, "read_api", return_value=sections), \
                patch.object(server, "download_attachment", return_value=b"%PDF-synthetic") as download:
            saved = server.download_resource(42, 7, "../../slides.pdf")
            with self.assertRaises(ToolError):
                server.download_resource(42, 8, "../../slides.pdf")
        download.assert_called_once()
        path = Path(saved["path"])
        self.assertEqual(path.parent, self.export / "downloads")
        self.assertEqual(path.read_bytes(), b"%PDF-synthetic")
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_course_resource_rejects_old_unlisted_course(self):
        eclass.write_export("courses/99.md", "Old course")
        with self.assertRaises(ToolError):
            server.course_resource(99)


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_initialization_tools_resources_and_argument_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "snapshot.json").write_text(json.dumps(fixture()))
            (root / "courses").mkdir()
            (root / "courses/42.md").write_text("# Calculus\n")
            launch = ("import sys; from pathlib import Path; "
                      "sys.path.insert(0, sys.argv[1]); import eclass, eclass_mcp; "
                      "eclass.EXPORT = Path(sys.argv[2]); eclass_mcp.mcp.run(transport='stdio')")
            params = StdioServerParameters(command=sys.executable,
                                          args=["-c", launch, str(Path(__file__).parent), temporary])
            async with asyncio.timeout(20):
                async with stdio_client(params) as (read, write):
                    async with ClientSession(read, write) as client:
                        initialized = await client.initialize()
                        self.assertEqual(initialized.serverInfo.name, "York eClass")
                        tools = (await client.list_tools()).tools
                        names = {tool.name for tool in tools}
                        self.assertEqual(len(names), 10)
                        self.assertNotIn("login", names)
                        self.assertTrue(next(t for t in tools if t.name == "list_courses").annotations.readOnlyHint)
                        self.assertFalse(next(t for t in tools if t.name == "sync_courses").annotations.readOnlyHint)
                        cached = await client.call_tool("list_courses", {"source": "snapshot"})
                        self.assertFalse(cached.isError)
                        self.assertEqual(cached.structuredContent["source"], "snapshot")
                        for arguments in ({"course_id": -1}, {"course_id": "../../private"},
                                          {"course_id": True}, {"course_id": 42, "source": "unknown"}):
                            rejected = await client.call_tool("get_course_contents", arguments)
                            self.assertTrue(rejected.isError)
                        resource = await client.read_resource("eclass://courses/42")
                        self.assertEqual(resource.contents[0].text, "# Calculus\n")


if __name__ == "__main__":
    unittest.main()
