#!/usr/bin/env python3
"""Read York eClass using a token obtained through Moodle's mobile SSO flow."""

import argparse
import base64
import binascii
from datetime import datetime, timezone
import getpass
import hashlib
import hmac
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import secrets
import sys
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.parse import unquote, urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener
import webbrowser
from zoneinfo import ZoneInfo


SITE = "https://eclass.yorku.ca"
YORK_SITES = (SITE, SITE + "/eclass")
STATE = Path(__file__).resolve().parent / ".state"
EXPORT = Path(__file__).resolve().parent / "eClass"
READ_FUNCTIONS = frozenset({
    "core_webservice_get_site_info",
    "core_enrol_get_users_courses",
    "core_course_get_contents",
    "mod_assign_get_assignments",
    "core_calendar_get_calendar_upcoming_view",
    "core_calendar_get_calendar_events",
    "mod_page_get_pages_by_courses",
    "mod_quiz_get_quizzes_by_courses",
    "mod_forum_get_forums_by_courses",
    "mod_forum_get_forum_discussions",
    "core_group_get_course_user_groups",
})


class EclassError(Exception):
    """An error safe to display without exposing an authentication token."""


class CallbackError(EclassError):
    """A pasted callback that can be retried without restarting login."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # An API token must only be sent to the fixed York HTTPS endpoint.
        return None


def save_private(name, value):
    if STATE.is_symlink():
        raise EclassError("The credential directory must not be a symbolic link.")
    STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
    STATE.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=".save-", dir=STATE)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream)
            stream.write("\n")
        os.replace(temporary, STATE / name)
    finally:
        Path(temporary).unlink(missing_ok=True)


def load_private(name):
    path = STATE / name
    if STATE.is_symlink() or path.is_symlink():
        raise EclassError("Credential files must not be symbolic links.")
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        raise EclassError("No saved login. Run the login command first.") from None
    except (ValueError, OSError):
        raise EclassError("Cannot read saved login. Run the login command again.") from None


def canonical_york_site(site):
    if isinstance(site, str):
        # Older York addresses may report HTTP; requests still always use HTTPS.
        site = site.removeprefix("http://")
        if not site.startswith("https://"):
            site = "https://" + site
        site = site.rstrip("/")
        if site in YORK_SITES:
            return site
    raise EclassError("The site address is not a supported York eClass address.")


def get_login_attempt():
    try:
        pending = load_private("pending.json")
    except EclassError:
        pending = None
    if (isinstance(pending, dict)
            and isinstance(pending.get("passport"), str)
            and re.fullmatch(r"[0-9a-f]{48}", pending["passport"])
            and isinstance(pending.get("created_at"), (int, float))
            and -60 <= time.time() - pending["created_at"] <= 15 * 60):
        return pending
    pending = {"passport": secrets.token_hex(24), "created_at": time.time()}
    save_private("pending.json", pending)
    return pending


def decode_callback(link, pending):
    age = time.time() - pending["created_at"]
    if not -60 <= age <= 15 * 60:
        raise EclassError("This login attempt expired. Run login again.")
    match = re.fullmatch(r"moodlemobile://token=(.+)", link.strip())
    if not match:
        raise CallbackError("Copy the full link from 'Click here to launch the app'.")
    try:
        payload = base64.b64decode(unquote(match[1]), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeError):
        raise CallbackError("The app link is incomplete or invalid. Copy it again.") from None
    parts = payload.split(":::")
    if len(parts) not in (2, 3) or not re.fullmatch(r"[0-9a-f]{32}", parts[0]):
        raise CallbackError("The app link contains an unexpected response format.")
    matched_site = None
    for site in YORK_SITES:
        # Moodle hashes its configured wwwroot, which can differ from the URL
        # used to enter the site. Only known York roots are considered.
        for root in (site, site + "/", site.replace("https://", "http://"),
                     site.replace("https://", "http://") + "/"):
            expected = hashlib.md5(
                (root + pending["passport"]).encode(), usedforsecurity=False
            ).hexdigest()
            if hmac.compare_digest(parts[0], expected):
                matched_site = site
                break
        if matched_site:
            break
    if matched_site is None:
        raise CallbackError(
            "This link belongs to a different login attempt. Keep this terminal open, "
            "reopen the York URL printed above, and copy its app launch link again."
        )
    if not re.fullmatch(r"[0-9a-fA-F]{32}", parts[1]):
        raise CallbackError("The app link contains an unexpected token format.")
    # A third field can contain a private browser auto-login token. Discard it.
    return {"site": matched_site, "token": parts[1]}


def read_api(token, function, parameters=None, *, site=SITE):
    if function not in READ_FUNCTIONS:
        raise EclassError("This helper only supports the listed read operations.")
    site = canonical_york_site(site)
    fields = dict(parameters or {})
    fields.update(wstoken=token, wsfunction=function, moodlewsrestformat="json")
    request = Request(
        site + "/webservice/rest/server.php",
        data=urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with build_opener(NoRedirect()).open(request, timeout=30) as response:
            result = json.load(response)
    except HTTPError as error:
        raise EclassError(f"York's API returned HTTP {error.code}.") from None
    except (URLError, TimeoutError, OSError):
        raise EclassError("Cannot reach York's API. Check the network and try again.") from None
    except (ValueError, UnicodeError):
        raise EclassError("York returned a page instead of an API response.") from None
    if isinstance(result, dict) and ("exception" in result or "errorcode" in result):
        code = str(result.get("errorcode", "unknown"))
        if code == "invalidtoken":
            raise EclassError("York rejected or expired this token. Run login again.")
        if code == "accessexception":
            raise EclassError("York denied this API operation for your account.")
        # Do not echo server errors or debugging text, which may contain secrets.
        code = code if re.fullmatch(r"[a-zA-Z0-9_/-]{1,80}", code) else "unknown"
        raise EclassError(f"York returned a Moodle API error ({code}).")
    return result


def safe_output(value, token):
    if isinstance(value, str):
        return value.replace(token, "[redacted]")
    if isinstance(value, list):
        return [safe_output(item, token) for item in value]
    if isinstance(value, dict):
        return {
            key: safe_output(item, token)
            for key, item in value.items()
            if key.lower() not in {"token", "wstoken", "privatetoken", "userprivateaccesskey"}
        }
    return value


def load_credentials():
    credentials = load_private("credentials.json")
    if not isinstance(credentials, dict):
        raise EclassError("Invalid saved credential. Run login again.")
    site = canonical_york_site(credentials.get("site"))
    token = credentials.get("token", "")
    if (not isinstance(token, str) or not re.fullmatch(r"[0-9a-fA-F]{32}", token)
            or not isinstance(credentials.get("userid"), int)):
        raise EclassError("Invalid saved credential. Run login again.")
    return {**credentials, "site": site}


class PlainText(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts = []
        self.hidden = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style"}:
            self.hidden.append(tag)
        elif not self.hidden and tag in {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "h4"}:
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if self.hidden:
            if tag == self.hidden[-1]:
                self.hidden.pop()
        elif tag in {"p", "div", "li", "tr", "h1", "h2", "h3", "h4"}:
            self.parts.append("\n")

    def handle_data(self, data):
        if not self.hidden:
            self.parts.append(data)


def plain_text(value):
    parser = PlainText()
    parser.feed(str(value or ""))
    return "\n".join(line.strip() for line in "".join(parser.parts).splitlines() if line.strip())


def due_time(value):
    if isinstance(value, (int, float)) and value > 0:
        try:
            return datetime.fromtimestamp(value, ZoneInfo("America/Toronto")).strftime("%Y-%m-%d %H:%M %Z")
        except (OverflowError, OSError, ValueError):
            pass
    return "Not specified"


def write_export(relative, text):
    if EXPORT.is_symlink():
        raise EclassError("The eClass export directory must not be a symbolic link.")
    EXPORT.mkdir(mode=0o700, parents=True, exist_ok=True)
    EXPORT.chmod(0o700)
    path = EXPORT / relative
    if path.parent.is_symlink():
        raise EclassError("The eClass course export directory must not be a symbolic link.")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    fd, temporary = tempfile.mkstemp(prefix=".export-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb" if isinstance(text, bytes) else "w") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def course_markdown(course, snapshot):
    course_id = str(course["id"])
    lines = ["# " + plain_text(course.get("fullname", course.get("shortname", course_id))),
             "", "Refreshed: " + snapshot["synced_at"],
             "Course: " + snapshot["site"] + "/course/view.php?id=" + course_id, ""]
    if course.get("summary"):
        lines.extend([plain_text(course["summary"]), ""])
    if "contents/" + course_id in snapshot["errors"]:
        lines.extend(["Course sections unavailable: " + snapshot["errors"]["contents/" + course_id], ""])
    for section in snapshot["contents"].get(course_id, []):
        lines.extend(["## " + (plain_text(section.get("name")) or "Course section"), ""])
        if section.get("summary"):
            lines.extend([plain_text(section["summary"]), ""])
        for module in section.get("modules", []):
            lines.extend(["### " + (plain_text(module.get("name")) or "Activity"), ""])
            if module.get("description"):
                lines.extend([plain_text(module["description"]), ""])
            if module.get("url"):
                lines.extend(["Activity URL: " + str(module["url"]), ""])
            for resource in module.get("contents", []):
                lines.append("- " + plain_text(resource.get("filename", resource.get("type", "Resource")))
                             + ": " + str(resource.get("fileurl", "")))
            if module.get("contents"):
                lines.append("")
    lines.extend(["## Assignments", ""])
    assignment_data = snapshot["assignments"].get(course_id, {})
    assignments = [assignment for item in assignment_data.get("courses", [])
                   for assignment in item.get("assignments", [])]
    if "assignments/" + course_id in snapshot["errors"]:
        lines.append("Unavailable: " + snapshot["errors"]["assignments/" + course_id])
    elif not assignments:
        lines.append("No assignments returned by York's mobile service.")
    for assignment in assignments:
        lines.extend(["### " + (plain_text(assignment.get("name")) or "Assignment"), "",
                      "Due: " + due_time(assignment.get("duedate")), ""])
        if assignment.get("intro"):
            lines.extend([plain_text(assignment["intro"]), ""])
        for resource in assignment.get("introattachments", []):
            lines.append("- " + plain_text(resource.get("filename", "Attachment"))
                         + ": " + str(resource.get("fileurl", "")))
        lines.append("")
    return "\n".join(lines) + "\n"


def sync_courses(credentials, *, progress=None):
    token, site = credentials["token"], credentials["site"]
    courses = read_api(token, "core_enrol_get_users_courses", {"userid": credentials["userid"]}, site=site)
    if (not isinstance(courses, list) or any(
            not isinstance(course, dict) or type(course.get("id")) is not int or course["id"] <= 0
            for course in courses)):
        raise EclassError("York returned an unexpected course list. The previous export was kept.")
    snapshot = {"site": site, "synced_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                "courses": courses, "contents": {}, "assignments": {}, "upcoming": None, "errors": {}}

    def fetch(key, function, parameters=None):
        try:
            return read_api(token, function, parameters, site=site)
        except EclassError as error:
            snapshot["errors"][key] = str(error)
            return None

    print(f"Reading {len(courses)} courses from York...", file=progress, flush=True)
    snapshot["upcoming"] = fetch("upcoming", "core_calendar_get_calendar_upcoming_view")
    for index, course in enumerate(courses, 1):
        course_id = str(course["id"])
        print(f"  {index}/{len(courses)}: " + plain_text(safe_output(course.get("fullname", course_id), token)), file=progress, flush=True)
        contents = fetch("contents/" + course_id, "core_course_get_contents", {"courseid": course["id"]})
        if contents is not None:
            if not isinstance(contents, list) or any(not isinstance(section, dict) for section in contents):
                snapshot["errors"]["contents/" + course_id] = "York returned an unexpected section list."
            else:
                snapshot["contents"][course_id] = contents
        assignments = fetch("assignments/" + course_id, "mod_assign_get_assignments", {"courseids[0]": course["id"]})
        if assignments is not None:
            if not isinstance(assignments, dict) or not isinstance(assignments.get("courses"), list):
                snapshot["errors"]["assignments/" + course_id] = "York returned an unexpected assignment list."
            else:
                snapshot["assignments"][course_id] = assignments
    snapshot = safe_output(snapshot, token)
    # Build documents before replacing any previous export. Credentials never
    # form part of this snapshot, and the API token is redacted from values.
    documents = {f"courses/{course['id']}.md": course_markdown(course, snapshot)
                 for course in snapshot["courses"]}
    lines = ["# York eClass course snapshot", "", "Refreshed: " + snapshot["synced_at"], "",
             "Run the sync command again to refresh this local copy:", "",
             "```sh", "python3 eclass.py sync", "```", "",
             "## Courses", ""]
    for course in snapshot["courses"]:
        title = plain_text(course.get("fullname", str(course["id"]))).replace("[", "(").replace("]", ")")
        lines.append(f"- [{title}](courses/{course['id']}.md)")
    lines.extend(["", "## Upcoming calendar events", ""])
    upcoming = snapshot["upcoming"]
    if isinstance(upcoming, dict):
        for event in upcoming.get("events", []):
            lines.extend(["### " + plain_text(event.get("name", "Event")), "",
                          "When: " + due_time(event.get("timestart")), "",
                          plain_text(event.get("description")), ""])
        if not upcoming.get("events"):
            lines.append("No upcoming calendar events returned by York.")
    if snapshot["errors"]:
        lines.extend(["", "## Data unavailable during this sync", ""])
        lines.extend("- " + key + ": " + error for key, error in snapshot["errors"].items())
    lines.extend(["", "This is a local snapshot. Resource links are included; attached files and recordings are not downloaded.",
                  "The current courses are listed above. Older unlisted course files may remain from previous syncs.", ""])
    for relative, document in documents.items():
        write_export(relative, document)
    write_export("snapshot.json", json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n")
    write_export(".gitignore", "*\n!.gitignore\n")
    write_export("README.md", "\n".join(lines))
    print(f"Saved {len(courses)} courses to {EXPORT / 'README.md'}", file=progress, flush=True)
    if snapshot["errors"]:
        print(f"{len(snapshot['errors'])} data requests were unavailable; details are listed in README.md.", file=progress)
    return snapshot


def login(open_browser=True):
    if not sys.stdin.isatty():
        raise EclassError("Run login in your own terminal so the pasted link stays hidden.")
    pending = get_login_attempt()
    url = SITE + "/admin/tool/mobile/launch.php?" + urlencode({
        "service": "moodle_mobile_app",
        "passport": pending["passport"],
        "confirmed": "1",
    })
    print("Open this York mobile-app login URL:\n" + url, flush=True)
    print(
        "\n1. Complete Passport York and Duo in the browser.\n"
        "2. Cancel any prompt to open the Moodle app.\n"
        "3. Right-click 'Click here to launch the app' and copy its link.\n"
        "4. Paste the link below. It will not be displayed.\n"
        "If York shows your dashboard, reopen the same URL above after signing in.\n"
        "Keep this terminal open while copying. Press Enter without pasting to reopen the URL.\n",
        flush=True,
    )
    def open_login():
        if open_browser:
            try:
                webbrowser.open(url)
            except webbrowser.Error:
                pass  # The printed URL can always be opened manually.

    open_login()
    while True:
        callback = getpass.getpass("Paste app launch link (hidden): ")
        if not callback.strip():
            print("Reopen this York login URL:\n" + url, flush=True)
            open_login()
            continue
        try:
            credential = decode_callback(callback, pending)
            break
        except CallbackError as error:
            print(str(error), file=sys.stderr)
    token = credential["token"]
    site = credential["site"]
    info = read_api(token, "core_webservice_get_site_info", site=site)
    if not isinstance(info, dict) or canonical_york_site(info.get("siteurl")) != site:
        raise EclassError("York's API returned an unexpected site identity. Login was not saved.")
    if not isinstance(info.get("userid"), int) or info["userid"] <= 0:
        raise EclassError("York's API did not return a valid user identity. Login was not saved.")
    save_private("credentials.json", {
        "site": site,
        "token": token,
        "userid": info["userid"],
        "saved_at": time.time(),
    })
    (STATE / "pending.json").unlink(missing_ok=True)
    print("Connected to York eClass. Token saved privately; the helper can now read courses.")


def positive_int(value):
    result = int(value)
    if result <= 0:
        raise argparse.ArgumentTypeError("course ID must be positive")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    login_parser = commands.add_parser("login", help="sign in through York's mobile-app flow")
    login_parser.add_argument("--no-open", action="store_true", help="print the URL without opening a browser")
    commands.add_parser("status", help="check the saved token against York")
    commands.add_parser("courses", help="list your enrolled courses")
    for command, help_text in (("contents", "read a course's sections and resources"),
                               ("assignments", "read assignments in a course")):
        subparser = commands.add_parser(command, help=help_text)
        subparser.add_argument("course_id", type=positive_int)
    commands.add_parser("upcoming", help="read the upcoming calendar view")
    commands.add_parser("sync", help="save course text, assignments, and calendar locally for Codex to read")
    commands.add_parser("forget", help="remove this helper's local token (does not revoke it at York)")
    args = parser.parse_args(argv)
    if args.command == "login":
        login(open_browser=not args.no_open)
        return
    if args.command == "forget":
        (STATE / "credentials.json").unlink(missing_ok=True)
        (STATE / "pending.json").unlink(missing_ok=True)
        print("Local credential removed. This does not revoke the token on York's server.")
        return
    credentials = load_credentials()
    site, token = credentials["site"], credentials["token"]
    if args.command == "sync":
        sync_courses(credentials)
        return
    if args.command == "status":
        info = read_api(token, "core_webservice_get_site_info", site=site)
        result = {"connected": True, "site": info.get("siteurl"), "userid": info.get("userid")}
    elif args.command == "courses":
        courses = read_api(token, "core_enrol_get_users_courses", {"userid": credentials["userid"]}, site=site)
        result = [{key: course[key] for key in ("id", "shortname", "fullname", "visible") if key in course}
                  for course in courses]
    elif args.command == "contents":
        result = read_api(token, "core_course_get_contents", {"courseid": args.course_id}, site=site)
    elif args.command == "assignments":
        result = read_api(token, "mod_assign_get_assignments", {"courseids[0]": args.course_id}, site=site)
    else:
        result = read_api(token, "core_calendar_get_calendar_upcoming_view", site=site)
    print(json.dumps(safe_output(result, token), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except EclassError as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print("\nLogin cancelled. No new token saved.", file=sys.stderr)
        sys.exit(130)
