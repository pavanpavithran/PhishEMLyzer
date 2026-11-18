import hashlib
import tempfile
import unittest

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from analyzer.body import extract_body
from analyzer.urls import extract_urls
from analyzer.attachments import extract_attachments
from analyzer.parser import (
    extract_metadata,
    extract_headers,
)
from reports.generator import generate_report


class TestPhase1(unittest.TestCase):

    def setUp(self):
        self.message = EmailMessage()
        self.message["From"] = "support@example.com"
        self.message["To"] = "user@example.org"
        self.message["Subject"] = "Test Message"

        self.message.set_content(
            "Visit https://example.com/help"
        )

        self.message.add_alternative(
            '<html><body>'
            '<a href="https://example.net/login">'
            'https://example.com/login'
            '</a></body></html>',
            subtype="html",
        )

        self.message.add_attachment(
            b"test attachment content",
            maintype="application",
            subtype="octet-stream",
            filename="test.bin",
        )

        # Exercise MIME serialization and parsing as well.
        self.message = BytesParser(
            policy=policy.default
        ).parsebytes(self.message.as_bytes())

    def test_metadata(self):
        result = extract_metadata(self.message)
        self.assertEqual(
            result["subject"], "Test Message"
        )

    def test_headers(self):
        headers = extract_headers(self.message)
        self.assertGreater(len(headers), 0)

    def test_body_extraction(self):
        body = extract_body(self.message)

        self.assertIn("example.com/help", body["plain"])
        self.assertIn("<a href=", body["html"])

    def test_url_extraction(self):
        body = extract_body(self.message)
        urls = extract_urls(body)

        destinations = [item["url"] for item in urls]

        self.assertIn(
            "https://example.com/help",
            destinations,
        )
        self.assertIn(
            "https://example.net/login",
            destinations,
        )

    def test_html_link_text(self):
        urls = extract_urls(extract_body(self.message))

        links = [
            item for item in urls
            if item["source"] == "html_href"
        ]

        self.assertEqual(
            links[0]["text"],
            "https://example.com/login",
        )

    def test_attachment_hash(self):
        attachments = extract_attachments(self.message)

        self.assertEqual(len(attachments), 1)
        self.assertEqual(
            attachments[0]["filename"],
            "test.bin",
        )

        expected = hashlib.sha256(
            b"test attachment content"
        ).hexdigest()

        self.assertEqual(
            attachments[0]["sha256"], expected
        )

    def test_json_report(self):
        body = extract_body(self.message)

        with tempfile.TemporaryDirectory() as temp:
            path = generate_report(
                source_file="sample.eml",
                metadata=extract_metadata(self.message),
                headers=extract_headers(self.message),
                body=body,
                urls=extract_urls(body),
                attachments=extract_attachments(self.message),
                output_dir=temp,
            )

            self.assertTrue(path.exists())


if __name__ == "__main__":
    unittest.main()
