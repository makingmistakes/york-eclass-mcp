"""Credential-handling and API-boundary checks; all tokens here are synthetic."""

import base64
import hashlib
import io
import json
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs

import eclass


TOKEN = "a" * 32
PRIVATE = "discard-this-private-token"


class LoginTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        state = patch.object(eclass, "STATE", Path(temporary.name) / "state")
        state.start()
        self.addCleanup(state.stop)
        self.pending = {"passport": "synthetic-nonce", "created_at": time.time()}
        self.siteid = hashlib.md5(
            (eclass.SITE + self.pending["passport"]).encode(), usedforsecurity=False
        ).hexdigest()

    def callback(self, siteid=None, token=TOKEN, private=None, root=None):
        if root is not None:
            siteid = hashlib.md5(
                (root + self.pending["passport"]).encode(), usedforsecurity=False
            ).hexdigest()
        parts = [siteid or self.siteid, token]
        if private:
            parts.append(private)
        return "moodlemobile://token=" + base64.b64encode(":::".join(parts).encode()).decode()

    def test_accepts_bound_response_and_discards_private_token(self):
        self.assertEqual(eclass.decode_callback(self.callback(private=PRIVATE), self.pending),
                         {"site": eclass.SITE, "token": TOKEN})

    def test_accepts_york_canonical_roots_without_weakening_nonce_check(self):
        for site in eclass.YORK_SITES:
            for root in (site, site + "/", site.replace("https://", "http://"),
                         site.replace("https://", "http://") + "/"):
                with self.subTest(root=root):
                    self.assertEqual(eclass.decode_callback(self.callback(root=root), self.pending),
                                     {"site": site, "token": TOKEN})

    def test_rejects_callbacks_from_other_domains(self):
        for root in ("https://example.org", "https://eclass.yorku.ca.example.org"):
            with self.subTest(root=root), self.assertRaises(eclass.CallbackError):
                eclass.decode_callback(self.callback(root=root), self.pending)

    def test_login_attempt_survives_a_restart(self):
        first = eclass.get_login_attempt()
        self.assertEqual(eclass.get_login_attempt(), first)

    def test_expired_login_attempt_is_replaced(self):
        expired = {"passport": "e" * 48, "created_at": time.time() - 16 * 60}
        eclass.save_private("pending.json", expired)
        self.assertNotEqual(eclass.get_login_attempt()["passport"], expired["passport"])

    def test_rejects_another_login_attempt(self):
        with self.assertRaises(eclass.EclassError):
            eclass.decode_callback(self.callback(siteid="b" * 32), self.pending)

    def test_rejects_expired_attempt(self):
        self.pending["created_at"] -= 16 * 60
        with self.assertRaises(eclass.EclassError):
            eclass.decode_callback(self.callback(), self.pending)

    def test_rejects_malformed_links_without_echoing_them(self):
        for value in ("https://example.org/" + TOKEN, "moodlemobile://token=%%%" + TOKEN,
                      self.callback(token="unexpected-secret")):
            with self.subTest(value=value), self.assertRaises(eclass.EclassError) as caught:
                eclass.decode_callback(value, self.pending)
            self.assertNotIn(TOKEN, str(caught.exception))
            self.assertNotIn("unexpected-secret", str(caught.exception))

    def test_saved_login_has_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(eclass, "STATE", Path(directory) / "state"):
            eclass.save_private("credentials.json", {"token": TOKEN})
            self.assertEqual(stat.S_IMODE(eclass.STATE.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((eclass.STATE / "credentials.json").stat().st_mode), 0o600)
            self.assertEqual(eclass.load_private("credentials.json"), {"token": TOKEN})

    def test_login_does_not_save_a_rejected_token(self):
        with patch.object(eclass.sys.stdin, "isatty", return_value=True), \
                patch.object(eclass.getpass, "getpass", return_value=self.callback()), \
                patch.object(eclass, "get_login_attempt", return_value=self.pending), \
                patch.object(eclass, "read_api", side_effect=eclass.EclassError("rejected")), \
                patch.object(eclass, "save_private") as save, patch("sys.stdout", io.StringIO()):
            with self.assertRaises(eclass.EclassError):
                eclass.login(open_browser=False)
            save.assert_not_called()

    def test_login_rejects_a_different_site(self):
        with patch.object(eclass.sys.stdin, "isatty", return_value=True), \
                patch.object(eclass.getpass, "getpass", return_value=self.callback()), \
                patch.object(eclass, "get_login_attempt", return_value=self.pending), \
                patch.object(eclass, "read_api", return_value={"siteurl": "https://example.org", "userid": 123}), \
                patch.object(eclass, "save_private") as save, patch("sys.stdout", io.StringIO()):
            with self.assertRaises(eclass.EclassError):
                eclass.login(open_browser=False)
            save.assert_not_called()

    def test_login_only_persists_validated_api_credential(self):
        with patch.object(eclass.sys.stdin, "isatty", return_value=True), \
                patch.object(eclass.getpass, "getpass", return_value=self.callback(private=PRIVATE)), \
                patch.object(eclass, "get_login_attempt", return_value=self.pending), \
                patch.object(eclass, "read_api", return_value={"siteurl": eclass.SITE, "userid": 123}), \
                patch.object(eclass, "save_private") as save, patch("sys.stdout", io.StringIO()) as output:
            eclass.login(open_browser=False)
            saved = save.call_args.args[1]
            self.assertEqual(saved["token"], TOKEN)
            self.assertNotIn(PRIVATE, json.dumps(saved))
            self.assertNotIn(TOKEN, output.getvalue())

    def test_login_retries_a_mismatched_link_without_changing_attempt(self):
        links = [self.callback(siteid="b" * 32), self.callback()]
        with patch.object(eclass.sys.stdin, "isatty", return_value=True), \
                patch.object(eclass.getpass, "getpass", side_effect=links) as prompt, \
                patch.object(eclass, "get_login_attempt", return_value=self.pending) as attempt, \
                patch.object(eclass, "read_api", return_value={"siteurl": eclass.SITE, "userid": 123}), \
                patch.object(eclass, "save_private") as save, \
                patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()) as errors:
            eclass.login(open_browser=False)
            self.assertEqual(prompt.call_count, 2)
            attempt.assert_called_once()
            save.assert_called_once()
            self.assertIn("different login attempt", errors.getvalue())
            self.assertNotIn(TOKEN, errors.getvalue())

    def test_login_uses_api_at_matching_canonical_root(self):
        for root in eclass.YORK_SITES:
            with self.subTest(root=root), patch.object(eclass.sys.stdin, "isatty", return_value=True), \
                    patch.object(eclass.getpass, "getpass", return_value=self.callback(root=root)), \
                    patch.object(eclass, "get_login_attempt", return_value=self.pending), \
                    patch.object(eclass, "read_api", return_value={"siteurl": root, "userid": 123}) as api, \
                    patch.object(eclass, "save_private") as save, patch("sys.stdout", io.StringIO()):
                eclass.login(open_browser=False)
                api.assert_called_once_with(TOKEN, "core_webservice_get_site_info", site=root)
                self.assertEqual(save.call_args.args[1]["site"], root)


class ApiTests(unittest.TestCase):
    def test_unrelated_sites_are_rejected_before_sending_token(self):
        with patch.object(eclass, "build_opener") as opener, self.assertRaises(eclass.EclassError):
            eclass.read_api(TOKEN, "core_webservice_get_site_info", site="https://example.org")
        opener.assert_not_called()

    def test_credential_only_goes_in_post_body_to_york(self):
        opener = unittest.mock.MagicMock()
        response = io.BytesIO(b'[{"id": 42}]')
        opener.open.return_value.__enter__.return_value = response
        with patch.object(eclass, "build_opener", return_value=opener):
            self.assertEqual(eclass.read_api(TOKEN, "core_enrol_get_users_courses", {"userid": 123}), [{"id": 42}])
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, eclass.SITE + "/webservice/rest/server.php")
        self.assertEqual(request.method, "POST")
        self.assertNotIn(TOKEN, request.full_url)
        self.assertEqual(parse_qs(request.data.decode())["wstoken"], [TOKEN])

    def test_write_operations_never_make_network_requests(self):
        with patch.object(eclass, "build_opener") as opener, self.assertRaises(eclass.EclassError):
            eclass.read_api(TOKEN, "mod_assign_save_submission")
        opener.assert_not_called()

    def test_redirects_are_not_followed(self):
        self.assertIsNone(eclass.NoRedirect().redirect_request(None, None, 307, "", {}, "https://example.org"))

    def test_server_errors_do_not_leak_tokens(self):
        for payload in ({"exception": "error", "errorcode": "invalidtoken", "message": TOKEN},
                        {"exception": "error", "errorcode": "bad code " + TOKEN, "debuginfo": TOKEN}):
            opener = unittest.mock.MagicMock()
            opener.open.return_value.__enter__.return_value = io.BytesIO(json.dumps(payload).encode())
            with patch.object(eclass, "build_opener", return_value=opener), \
                    self.assertRaises(eclass.EclassError) as caught:
                eclass.read_api(TOKEN, "core_webservice_get_site_info")
            self.assertNotIn(TOKEN, str(caught.exception))

    def test_output_removes_authentication_material(self):
        value = {"token": TOKEN, "userprivateaccesskey": PRIVATE, "items": [{"url": "https://example.org/?token=" + TOKEN}]}
        result = json.dumps(eclass.safe_output(value, TOKEN))
        self.assertNotIn(TOKEN, result)
        self.assertNotIn(PRIVATE, result)
        self.assertIn("[redacted]", result)


class ExportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        export = patch.object(eclass, "EXPORT", Path(temporary.name) / "eClass")
        export.start()
        self.addCleanup(export.stop)
        self.credentials = {"site": eclass.SITE, "token": TOKEN, "userid": 123,
                            "private_token": PRIVATE}

    def api(self, token, function, parameters=None, *, site):
        self.assertEqual(token, TOKEN)
        self.assertEqual(site, eclass.SITE)
        return {
            "core_enrol_get_users_courses": [{"id": 42, "fullname": "Mathematics", "summary": "<p>Course introduction</p>"}],
            "core_calendar_get_calendar_upcoming_view": {"events": [{"name": "Quiz", "timestart": 1793102400}]},
            "core_course_get_contents": [{"name": "Week 1", "summary": "<p>Read chapter one.</p>", "modules": [
                {"name": "Lecture notes", "description": "<p>Review these notes.</p>", "contents": [
                    {"filename": "notes.pdf", "fileurl": "https://eclass.yorku.ca/resource?token=" + TOKEN}]}]}],
            "mod_assign_get_assignments": {"courses": [{"id": 42, "assignments": [
                {"name": "Problem set", "intro": "<p>Solve exercises 1 &amp; 2.</p>", "duedate": 1793102400}]}]},
        }[function]

    def test_exports_readable_documents_without_credentials(self):
        with patch.object(eclass, "read_api", side_effect=self.api), patch("sys.stdout", io.StringIO()) as output:
            eclass.sync_courses(self.credentials)
        index = (eclass.EXPORT / "README.md").read_text()
        course = (eclass.EXPORT / "courses/42.md").read_text()
        snapshot = json.loads((eclass.EXPORT / "snapshot.json").read_text())
        self.assertIn("courses/42.md", index)
        self.assertIn("Quiz", index)
        self.assertIn("Course introduction", course)
        self.assertIn("Read chapter one.", course)
        self.assertIn("notes.pdf", course)
        self.assertIn("Solve exercises 1 & 2.", course)
        self.assertIn("2026-", course)
        self.assertEqual(snapshot["errors"], {})
        self.assertNotIn("token", snapshot)
        for path in eclass.EXPORT.rglob("*"):
            if path.is_file():
                self.assertNotIn(TOKEN, path.read_text())
                self.assertNotIn(PRIVATE, path.read_text())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(eclass.EXPORT.stat().st_mode), 0o700)
        self.assertNotIn(TOKEN, output.getvalue())

    def test_denied_sections_do_not_discard_other_course_data(self):
        def optional_failure(token, function, parameters=None, *, site):
            if function == "core_course_get_contents":
                raise eclass.EclassError("York denied this API operation for your account.")
            return self.api(token, function, parameters, site=site)

        with patch.object(eclass, "read_api", side_effect=optional_failure), patch("sys.stdout", io.StringIO()):
            eclass.sync_courses(self.credentials)
        snapshot = json.loads((eclass.EXPORT / "snapshot.json").read_text())
        self.assertIn("contents/42", snapshot["errors"])
        self.assertIn("42", snapshot["assignments"])
        self.assertIn("Problem set", (eclass.EXPORT / "courses/42.md").read_text())
        self.assertIn("contents/42", (eclass.EXPORT / "README.md").read_text())

    def test_failed_course_request_preserves_previous_export(self):
        eclass.write_export("README.md", "Previous snapshot\n")
        with patch.object(eclass, "read_api", side_effect=eclass.EclassError("Network unavailable")), \
                self.assertRaises(eclass.EclassError):
            eclass.sync_courses(self.credentials)
        self.assertEqual((eclass.EXPORT / "README.md").read_text(), "Previous snapshot\n")

    def test_bad_course_ids_cannot_write_paths(self):
        with patch.object(eclass, "read_api", return_value=[{"id": "../../elsewhere"}]), \
                self.assertRaises(eclass.EclassError):
            eclass.sync_courses(self.credentials)
        self.assertFalse(eclass.EXPORT.exists())

    def test_html_is_converted_to_text_without_script_content(self):
        value = "<p>Read &amp; solve.</p><script>hidden()</script><style>body{}</style><p>Then submit.</p>"
        self.assertEqual(eclass.plain_text(value), "Read & solve.\nThen submit.")


if __name__ == "__main__":
    unittest.main()
