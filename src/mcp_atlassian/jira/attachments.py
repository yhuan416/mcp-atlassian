"""Attachment operations for Jira API."""

import hashlib
import logging
import mimetypes
import os
import re
from pathlib import Path
from typing import Any

from ..models.jira import JiraAttachment
from ..utils.io import (
    get_file_root,
    is_in_cwd_root,
    open_confined,
    validate_safe_path,
)
from ..utils.media import (
    ATTACHMENT_MAX_BYTES,
    AttachmentBudget,
    AttachmentTooLargeError,
    read_capped,
)
from ..utils.ssrf_adapter import ensure_attachment_origin, loggable_url
from .client import JiraClient
from .protocols import AttachmentsOperationsProto

# Configure logging
logger = logging.getLogger("mcp-jira")


class AttachmentsMixin(JiraClient, AttachmentsOperationsProto):
    """Mixin for Jira attachment operations."""

    def _ensure_same_origin(self, url: str) -> None:
        """Reject an attachment URL that is not on this fetcher's Jira origin.

        Attachment URLs come from the Jira response. Only the fetcher's own
        URL is trusted (not the operator's JIRA_URL or CONFLUENCE_URL), so a
        fetcher for a request-supplied host cannot be sent elsewhere. Hosts
        under MCP_ALLOWED_URL_DOMAINS are also accepted.

        Args:
            url: The absolute URL about to be fetched.

        Raises:
            ValueError: If *url* is on another origin.
        """
        ensure_attachment_origin(
            url, (self.config.url, getattr(self.jira, "url", None))
        )

    def download_attachment(self, url: str, target_path: str) -> bool:
        """
        Download a Jira attachment to the specified path.

        Args:
            url: The URL of the attachment to download
            target_path: The path where the attachment should be saved

        Returns:
            True if successful, False otherwise
        """
        if not url:
            logger.error("No URL provided for attachment download")
            return False

        try:
            # Relative paths resolve against the configured file root (the
            # working directory unless MCP_ATLASSIAN_FILES_DIR or a remote
            # transport sets another one).
            if not os.path.isabs(target_path):
                target_path = os.path.normpath(
                    os.path.join(get_file_root(), target_path)
                )

            # Guard against path traversal (resolves symlinks)
            validate_safe_path(target_path)

            # Do not write into the working-directory root itself: that is where
            # Python resolves imports first, so a download landing there could
            # overwrite an importable module and gain code execution (GHSA-6vmq).
            # Attachments must be saved into a subdirectory.
            if is_in_cwd_root(target_path):
                logger.error(
                    f"Refusing to download into the working-directory root: {target_path}"
                )
                return False

            logger.info(
                f"Downloading attachment from {loggable_url(url)} to {target_path}"
            )

            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            self._ensure_same_origin(url)
            # Use the Jira session to download the file
            response = self.jira._session.get(url, stream=True)
            try:
                response.raise_for_status()

                # Write the file to disk. open_confined re-checks the boundary
                # on the descriptor it opens, so a symlink swapped in since the
                # validation above cannot redirect the write.
                with open_confined(target_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
            finally:
                response.close()

            # Verify the file was created
            if os.path.exists(target_path):
                file_size = os.path.getsize(target_path)
                logger.info(
                    f"Successfully downloaded attachment to {target_path} (size: {file_size} bytes)"
                )
                return True
            else:
                logger.error(f"File was not created at {target_path}")
                return False

        except Exception as e:
            logger.error(f"Error downloading attachment: {str(e)}")
            return False

    @staticmethod
    def _looks_like_html(
        head: bytes, content_type: str, expected_mime: str | None
    ) -> bool:
        """Detect a login page masquerading as an attachment."""
        expected_html = "html" in (expected_mime or "").lower()
        text = head[:2048].decode("utf-8", errors="ignore").lstrip().lower()
        if "<title>登录" in text or "login.jsp" in text:
            return True
        if expected_html:
            return False
        if text.startswith("<!doctype html") or text.startswith("<html"):
            return True
        return "text/html" in (content_type or "").lower()

    def download_attachment_strict(
        self,
        url: str,
        target_path: str,
        expected_size: int | None = None,
        expected_mime: str | None = None,
    ) -> tuple[bool, str]:
        """Download an attachment with validation; returns ``(ok, error)``."""
        if not url:
            return False, "No URL provided for attachment download"

        tmp_path = f"{target_path}.part"
        try:
            # Relative paths resolve against the configured file root (the
            # working directory unless MCP_ATLASSIAN_FILES_DIR or a remote
            # transport sets another one).
            if not os.path.isabs(target_path):
                target_path = os.path.normpath(
                    os.path.join(get_file_root(), target_path)
                )
                tmp_path = f"{target_path}.part"

            # Guard against path traversal (resolves symlinks)
            validate_safe_path(target_path)

            # Do not write into the working-directory root itself: that is where
            # Python resolves imports first, so a download landing there could
            # overwrite an importable module and gain code execution (GHSA-6vmq).
            # Attachments must be saved into a subdirectory.
            if is_in_cwd_root(target_path):
                return (
                    False,
                    f"Refusing to download into the working-directory root: {target_path}",
                )

            logger.info(
                f"Downloading attachment from {loggable_url(url)} to {target_path}"
            )
            os.makedirs(os.path.dirname(target_path), exist_ok=True)

            self._ensure_same_origin(url)
            # Session-cookie mode: Jira Server/DC with an enforced CAPTCHA (or a
            # login-policy that denies HTTP Basic) can only be reached through
            # the same web session a browser would use. The cookie is read from
            # the environment so the container needs no interactive login.
            cookie = os.getenv("JIRA_SESSION_COOKIE", "").strip()
            # allow_redirects=False is the whole point: Jira Server/DC answers
            # unauthenticated downloads with 302 -> /login.jsp, which requests
            # would otherwise happily turn into a 200 HTML "attachment".
            extra = {"headers": {"Cookie": cookie}} if cookie else {}
            response = self.jira._session.get(
                url, stream=True, allow_redirects=False, **extra
            )
            written = 0
            head = b""
            ctype = ""
            try:
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location", "")
                    hint = (
                        "the configured JIRA_SESSION_COOKIE is expired or rejected"
                        if cookie
                        else "use HTTP Basic, JIRA_SESSION_COOKIE, or a working login"
                    )
                    return (
                        False,
                        "HTTP redirect to "
                        f"{location or 'login page'} — not authenticated for "
                        f"/secure/attachment (PAT/Bearer is REST-only on Jira "
                        f"Server/DC; {hint})",
                    )
                response.raise_for_status()
                ctype = response.headers.get("Content-Type", "") or ""
                if not isinstance(ctype, str):
                    ctype = ""

                # open_confined re-checks the boundary on the descriptor it opens,
                # so a symlink swapped in since the validation above cannot
                # redirect the write.
                with open_confined(tmp_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if not chunk:
                            continue
                        if len(head) < 2048:
                            head += chunk[: 2048 - len(head)]
                        f.write(chunk)
                        written += len(chunk)
            finally:
                response.close()

            if self._looks_like_html(head, ctype, expected_mime):
                return (
                    False,
                    "server returned an HTML login page instead of the attachment "
                    f"(Content-Type: {ctype or 'unknown'}) — refusing to save it",
                )
            if expected_size and written != expected_size:
                return (
                    False,
                    f"size mismatch: received {written} bytes, Jira metadata says "
                    f"{expected_size}",
                )

            os.replace(tmp_path, target_path)
            logger.info(
                f"Successfully downloaded attachment to {target_path} (size: {written} bytes)"
            )
            return True, ""

        except Exception as e:  # noqa: BLE001 - surface the reason to the caller
            return False, str(e)
        finally:
            try:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)
            except OSError:
                pass

    def fetch_attachment_content(self, url: str) -> bytes | None:
        """
        Fetch attachment content into memory.

        Args:
            url: The URL of the attachment to download

        Returns:
            The raw bytes of the attachment, or None on failure

        Raises:
            AttachmentTooLargeError: The body passed the inline size limit.
        """
        if not url:
            logger.error("No URL provided for attachment fetch")
            return None

        try:
            self._ensure_same_origin(url)
            logger.info(f"Fetching attachment from {loggable_url(url)}")
            response = self.jira._session.get(url, stream=True)
            try:
                response.raise_for_status()

                data = read_capped(response, ATTACHMENT_MAX_BYTES)
                logger.info(
                    f"Successfully fetched attachment from {loggable_url(url)} "
                    f"(size: {len(data)} bytes)"
                )
                return data
            finally:
                response.close()

        except AttachmentTooLargeError:
            logger.warning(
                f"Attachment from {loggable_url(url)} is larger than "
                f"{ATTACHMENT_MAX_BYTES} bytes; stopped reading"
            )
            raise
        except Exception as e:
            logger.error(f"Error fetching attachment: {str(e)}")
            return None

    def get_issue_attachments(self, issue_key: str) -> list[JiraAttachment]:
        """Return attachment metadata for a Jira issue without downloading.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123').

        Returns:
            A list of JiraAttachment instances.
        """
        logger.info(f"Fetching attachment metadata for {issue_key}")
        issue_data = self.jira.issue(issue_key, fields="attachment")

        if not isinstance(issue_data, dict):
            msg = f"Unexpected return value type from `jira.issue`: {type(issue_data)}"
            logger.error(msg)
            raise TypeError(msg)

        if "fields" not in issue_data:
            logger.error(f"Could not retrieve issue {issue_key}")
            return []

        attachment_data = issue_data.get("fields", {}).get("attachment", [])
        return [
            JiraAttachment.from_api_response(item)
            for item in attachment_data
            if isinstance(item, dict)
        ]

    def get_issue_attachment_contents(self, issue_key: str) -> dict[str, Any]:
        """
        Fetch all attachment contents for a Jira issue into memory.

        Unlike download_issue_attachments, this method does not write to
        the filesystem.  Each attachment is returned as raw bytes so the
        caller (e.g. the MCP server layer) can serialise them however it
        needs (base64 embedded resources, etc.).

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')

        Returns:
            A dictionary with:
                success (bool)
                issue_key (str)
                total (int)
                attachments (list[dict]): each dict has 'filename',
                    'content_type', 'size', and 'data' (bytes)
                failed (list[dict]): each dict has 'filename' and 'error'
        """
        logger.info(f"Fetching attachment contents for {issue_key}")

        issue_data = self.jira.issue(issue_key, fields="attachment")

        if not isinstance(issue_data, dict):
            msg = f"Unexpected return value type from `jira.issue`: {type(issue_data)}"
            logger.error(msg)
            raise TypeError(msg)

        if "fields" not in issue_data:
            logger.error(f"Could not retrieve issue {issue_key}")
            return {
                "success": False,
                "error": f"Could not retrieve issue {issue_key}",
            }

        attachment_data = issue_data.get("fields", {}).get("attachment", [])

        if not attachment_data:
            return {
                "success": True,
                "message": f"No attachments found for issue {issue_key}",
                "attachments": [],
                "failed": [],
            }

        attachments: list[JiraAttachment] = []
        for item in attachment_data:
            if isinstance(item, dict):
                attachments.append(JiraAttachment.from_api_response(item))

        if not attachments:
            return {
                "success": True,
                "message": f"No attachments found for issue {issue_key}",
                "attachments": [],
                "failed": [],
            }

        fetched: list[dict[str, Any]] = []
        failed: list[dict[str, Any]] = []
        budget = AttachmentBudget()

        def too_large(attachment: JiraAttachment, size: int) -> bool:
            refusal = budget.refusal(size)
            if refusal is None:
                return False
            logger.warning(f"Skipping attachment {attachment.filename}: {refusal}")
            failed.append(
                {
                    "filename": attachment.filename,
                    "error": (
                        f"Attachment '{attachment.filename}' is {refusal} "
                        "Retrieve it directly from Jira."
                    ),
                }
            )
            return True

        for attachment in attachments:
            if not attachment.url:
                logger.warning(f"No URL for attachment {attachment.filename}")
                failed.append(
                    {"filename": attachment.filename, "error": "No URL available"}
                )
                continue

            if too_large(attachment, attachment.size):
                continue

            try:
                data = self.fetch_attachment_content(attachment.url)
            except AttachmentTooLargeError:
                failed.append(
                    {
                        "filename": attachment.filename,
                        "error": (
                            f"Attachment '{attachment.filename}' is larger "
                            "than the 50 MB inline limit. Retrieve it "
                            "directly from Jira."
                        ),
                    }
                )
                continue
            if data is not None and too_large(attachment, len(data)):
                continue
            if data is not None:
                budget.spend(len(data))
                content_type = (
                    attachment.content_type
                    or mimetypes.guess_type(attachment.filename)[0]
                    or "application/octet-stream"
                )
                fetched.append(
                    {
                        "filename": attachment.filename,
                        "content_type": content_type,
                        "size": len(data),
                        "data": data,
                    }
                )
            else:
                failed.append(
                    {"filename": attachment.filename, "error": "Fetch failed"}
                )

        return {
            "success": True,
            "issue_key": issue_key,
            "total": len(attachments),
            "attachments": fetched,
            "failed": failed,
        }

    def download_issue_attachments(
        self,
        issue_key: str,
        target_dir: str,
        pattern: str | None = None,
        overwrite: bool = False,
    ) -> dict[str, Any]:
        """
        Download all attachments for a Jira issue to a directory.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')
            target_dir: The directory where attachments should be saved
            pattern: Optional regex matched against the filename
            overwrite: Re-download files that already exist

        Returns:
            A dictionary with download results (path + sha256 per file)
        """
        # Relative paths resolve against the configured file root (the
        # working directory unless MCP_ATLASSIAN_FILES_DIR or a remote
        # transport sets another one).
        if not os.path.isabs(target_dir):
            target_dir = os.path.normpath(os.path.join(get_file_root(), target_dir))

        # Guard against path traversal (resolves symlinks)
        validate_safe_path(target_dir)

        logger.info(
            f"Downloading attachments for {issue_key} to directory: {target_dir}"
        )

        # Create the target directory if it doesn't exist
        target_path = Path(target_dir)
        target_path.mkdir(parents=True, exist_ok=True)

        # Get the issue with attachments
        logger.info(f"Fetching issue {issue_key} with attachments")
        issue_data = self.jira.issue(issue_key, fields="attachment")

        if not isinstance(issue_data, dict):
            msg = f"Unexpected return value type from `jira.issue`: {type(issue_data)}"
            logger.error(msg)
            raise TypeError(msg)

        if "fields" not in issue_data:
            logger.error(f"Could not retrieve issue {issue_key}")
            return {"success": False, "error": f"Could not retrieve issue {issue_key}"}

        # Process attachments
        attachments = []
        results = []

        # Extract attachments from the API response
        attachment_data = issue_data.get("fields", {}).get("attachment", [])

        if not attachment_data:
            return {
                "success": True,
                "message": f"No attachments found for issue {issue_key}",
                "downloaded": [],
                "failed": [],
            }

        # Create JiraAttachment objects for each attachment
        for attachment in attachment_data:
            if isinstance(attachment, dict):
                attachments.append(JiraAttachment.from_api_response(attachment))

        if pattern:
            rx = re.compile(pattern)
            attachments = [a for a in attachments if rx.search(a.filename)]

        # Download each attachment
        downloaded = []
        skipped = []
        failed = []

        for attachment in attachments:
            if not attachment.url:
                logger.warning(f"No URL for attachment {attachment.filename}")
                failed.append(
                    {"filename": attachment.filename, "error": "No URL available"}
                )
                continue

            # Create a safe filename
            safe_filename = Path(attachment.filename).name
            file_path = target_path / safe_filename

            if file_path.exists() and not overwrite:
                existing_size = file_path.stat().st_size
                if not attachment.size or existing_size == attachment.size:
                    skipped.append(
                        {
                            "filename": attachment.filename,
                            "path": str(file_path),
                            "size": existing_size,
                            "reason": "already exists",
                        }
                    )
                    continue

            # Strict download: no redirect following, size/type validated.
            ok, error = self.download_attachment_strict(
                attachment.url,
                str(file_path),
                expected_size=attachment.size or None,
                expected_mime=attachment.content_type,
            )

            if ok:
                entry = {
                    "filename": attachment.filename,
                    "path": str(file_path),
                    "size": file_path.stat().st_size
                    if file_path.exists()
                    else attachment.size,
                }
                if file_path.exists():
                    digest = hashlib.sha256()
                    with open(file_path, "rb") as fh:
                        for block in iter(lambda: fh.read(1024 * 1024), b""):
                            digest.update(block)
                    entry["sha256"] = digest.hexdigest()
                downloaded.append(entry)
            else:
                failed.append({"filename": attachment.filename, "error": error})

        return {
            "success": not failed,
            "issue_key": issue_key,
            "target_dir": str(target_path),
            "total": len(attachments),
            "downloaded": downloaded,
            "skipped": skipped,
            "failed": failed,
        }

    def upload_attachment(self, issue_key: str, file_path: str) -> dict[str, Any]:
        """
        Upload a single attachment to a Jira issue.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')
            file_path: The path to the file to upload

        Returns:
            A dictionary with upload result information
        """
        if not issue_key:
            logger.error("No issue key provided for attachment upload")
            return {"success": False, "error": "No issue key provided"}

        if not file_path:
            logger.error("No file path provided for attachment upload")
            return {"success": False, "error": "No file path provided"}

        try:
            # Confine the upload source to the workspace before it is read: reject
            # traversal/absolute paths that escape CWD (arbitrary file read /
            # exfiltration via a caller-supplied file_path).
            file_path = str(validate_safe_path(file_path))

            # Check if file exists
            if not os.path.exists(file_path):
                logger.error(f"File not found: {file_path}")
                return {"success": False, "error": f"File not found: {file_path}"}

            logger.info(f"Uploading attachment from {file_path} to issue {issue_key}")

            # Use the Jira API to upload the file
            filename = os.path.basename(file_path)
            # Upload from the verified descriptor; add_attachment(filename=...)
            # would reopen the path after the check.
            with open_confined(file_path, "rb") as file:
                attachment = self.jira.add_attachment_object(issue_key, file)

            if attachment:
                file_size = os.path.getsize(file_path)
                logger.info(
                    f"Successfully uploaded attachment {filename} to {issue_key} (size: {file_size} bytes)"
                )
                return {
                    "success": True,
                    "issue_key": issue_key,
                    "filename": filename,
                    "size": file_size,
                    "id": attachment.get("id")
                    if isinstance(attachment, dict)
                    else None,
                }
            else:
                logger.error(f"Failed to upload attachment {filename} to {issue_key}")
                return {
                    "success": False,
                    "error": f"Failed to upload attachment {filename} to {issue_key}",
                }

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error uploading attachment: {error_msg}")
            return {"success": False, "error": error_msg}

    def upload_attachments(
        self, issue_key: str, file_paths: list[str]
    ) -> dict[str, Any]:
        """
        Upload multiple attachments to a Jira issue.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')
            file_paths: List of paths to files to upload

        Returns:
            A dictionary with upload results
        """
        if not issue_key:
            logger.error("No issue key provided for attachment upload")
            return {"success": False, "error": "No issue key provided"}

        if not file_paths:
            logger.error("No file paths provided for attachment upload")
            return {"success": False, "error": "No file paths provided"}

        logger.info(f"Uploading {len(file_paths)} attachments to issue {issue_key}")

        # Upload each attachment
        uploaded = []
        failed = []

        for file_path in file_paths:
            result = self.upload_attachment(issue_key, file_path)

            if result.get("success"):
                uploaded.append(
                    {
                        "filename": result.get("filename"),
                        "size": result.get("size"),
                        "id": result.get("id"),
                    }
                )
            else:
                failed.append(
                    {
                        "filename": os.path.basename(file_path),
                        "error": result.get("error"),
                    }
                )

        return {
            "success": bool(uploaded),
            "issue_key": issue_key,
            "total": len(file_paths),
            "uploaded": uploaded,
            "failed": failed,
        }

    def upload_attachment_from_content(
        self, issue_key: str, filename: str, content: bytes
    ) -> dict[str, Any]:
        """
        Upload a single attachment to a Jira issue from in-memory bytes.

        This is the filesystem-free counterpart to ``upload_attachment``. It is
        intended for deployments where the server cannot read host file paths
        (for example, a remote or containerized MCP server): the caller provides
        the raw file content directly instead of a path.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')
            filename: Name of the attachment (determines title and file type)
            content: Raw file bytes to upload

        Returns:
            A dictionary with upload result information
        """
        if not issue_key:
            logger.error("No issue key provided for attachment upload")
            return {"success": False, "error": "No issue key provided"}

        if not filename:
            logger.error("No filename provided for attachment upload")
            return {"success": False, "error": "No filename provided"}

        if not content:
            logger.error("No file content provided for attachment upload")
            return {"success": False, "error": "No file content provided"}

        try:
            logger.info(
                f"Uploading attachment {filename} ({len(content)} bytes) "
                f"to issue {issue_key}"
            )

            base_url = self.jira.resource_url("issue")
            attachment = self.jira.post(
                f"{base_url}/{issue_key}/attachments",
                headers=self.jira.no_check_headers,
                files={"file": (filename, content)},
            )

            if attachment:
                # The REST API answers with a list holding one entry per
                # uploaded file; a single upload therefore yields a 1-item list.
                if isinstance(attachment, list):
                    attachment = attachment[0]

                logger.info(
                    f"Successfully uploaded attachment {filename} to "
                    f"{issue_key} (size: {len(content)} bytes)"
                )
                return {
                    "success": True,
                    "issue_key": issue_key,
                    "filename": filename,
                    "size": len(content),
                    "id": attachment.get("id")
                    if isinstance(attachment, dict)
                    else None,
                }

            logger.error(f"Failed to upload attachment {filename} to {issue_key}")
            return {
                "success": False,
                "error": f"Failed to upload attachment {filename} to {issue_key}",
            }

        except Exception as e:
            error_msg = str(e)
            logger.error(f"Error uploading attachment from content: {error_msg}")
            return {"success": False, "error": error_msg}

    def upload_attachments_from_content(
        self, issue_key: str, attachments: list[dict[str, Any]]
    ) -> dict[str, Any]:
        """
        Upload multiple attachments to a Jira issue from in-memory bytes.

        Args:
            issue_key: The Jira issue key (e.g., 'PROJ-123')
            attachments: List of dicts with 'filename' and 'content' (bytes) keys

        Returns:
            A dictionary with upload results, in the same shape as
            ``upload_attachments``
        """
        if not issue_key:
            logger.error("No issue key provided for attachment upload")
            return {"success": False, "error": "No issue key provided"}

        if not attachments:
            logger.error("No attachment content provided for attachment upload")
            return {"success": False, "error": "No attachment content provided"}

        logger.info(f"Uploading {len(attachments)} attachments to issue {issue_key}")

        uploaded = []
        failed = []

        for attachment in attachments:
            filename = attachment.get("filename", "")
            result = self.upload_attachment_from_content(
                issue_key, filename, attachment.get("content", b"")
            )

            if result.get("success"):
                uploaded.append(
                    {
                        "filename": result.get("filename"),
                        "size": result.get("size"),
                        "id": result.get("id"),
                    }
                )
            else:
                failed.append(
                    {
                        "filename": filename,
                        "error": result.get("error"),
                    }
                )

        return {
            "success": bool(uploaded),
            "issue_key": issue_key,
            "total": len(attachments),
            "uploaded": uploaded,
            "failed": failed,
        }
