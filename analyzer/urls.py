import re
from html.parser import HTMLParser
from urllib.parse import urlsplit


URL_PATTERN = re.compile(
    r"https?://[^\s<>\"']+",
    re.IGNORECASE
)


class EmailHTMLParser(HTMLParser):
    """Extract links and URLs from email HTML."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
        self.resources = []
        self.current_link = None

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)

        if tag == "a" and attributes.get("href"):
            # Close malformed/nested anchor context
            if self.current_link is not None:
                self.links.append(self.current_link)

            self.current_link = {
                "url": attributes["href"],
                "text": "",
                "source": "html_href",
            }

        if attributes.get("src"):
            self.resources.append({
                "url": attributes["src"],
                "source": "html_src",
            })

    def handle_data(self, data):
        if self.current_link is not None:
            self.current_link["text"] += data

    def handle_endtag(self, tag):
        if tag == "a" and self.current_link is not None:
            self.links.append(self.current_link)
            self.current_link = None

    def close(self):
        super().close()
        if self.current_link is not None:
            self.links.append(self.current_link)
            self.current_link = None


def is_http_url(value):
    """Check whether a string is an HTTP(S) URL."""
    try:
        parsed = urlsplit(value)
        return (
            parsed.scheme.lower() in ("http", "https")
            and bool(parsed.hostname)
        )
    except ValueError:
        return False


def extract_urls(body):
    """
    Extract URLs from plain text and HTML.

    Preserves link source and visible text.
    Does not make any network requests.
    """
    results = []

    for match in URL_PATTERN.findall(body.get("plain", "")):
        url = match.rstrip(".,;!?)]}")

        if is_http_url(url):
            results.append({
                "url": url,
                "source": "plain_text",
                "text": "",
            })

    parser = EmailHTMLParser()
    parser.feed(body.get("html", ""))
    parser.close()

    for item in parser.links + parser.resources:
        if is_http_url(item["url"]):
            results.append(item)

    # Extract additional URLs appearing as text in HTML
    # without duplicating already-extracted identical entries.
    for match in URL_PATTERN.findall(
        re.sub(r"<[^>]*>", " ", body.get("html", ""))
    ):
        url = match.rstrip(".,;!?)]}")
        if is_http_url(url):
            results.append({
                "url": url,
                "source": "html_text",
                "text": "",
            })

    unique = []
    seen = set()

    for item in results:
        key = (
            item["url"],
            item["source"],
            item.get("text", ""),
        )
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique
