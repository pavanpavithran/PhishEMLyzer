import argparse

from analyzer.parser import (
    load_email,
    extract_metadata,
    extract_headers,
)
from analyzer.body import extract_body
from analyzer.urls import extract_urls
from analyzer.attachments import extract_attachments
from reports.generator import generate_report


def main():
    parser = argparse.ArgumentParser(
        description="PhishEMLyzer - Email Forensics Analyzer"
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the .eml file",
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable the ASCII banner",
    )

    args = parser.parse_args()


    print("[+] PhishEMLyzer v0.1")
    print("[+] Loading email...\n")

    try:
        message = load_email(args.file)

        metadata = extract_metadata(message)
        headers = extract_headers(message)
        body = extract_body(message)
        urls = extract_urls(body)
        attachments = extract_attachments(message)

        report_path = generate_report(
            source_file=args.file,
            metadata=metadata,
            headers=headers,
            body=body,
            urls=urls,
            attachments=attachments,
        )

    except (OSError, ValueError) as error:
        parser.error(str(error))

    print("=== EMAIL METADATA ===")
    for key, value in metadata.items():
        print(f"{key.upper():15}: {value}")

    print("\n=== EXTRACTION SUMMARY ===")
    print(f"Headers     : {len(headers)}")
    print(f"Plain Body  : {bool(body['plain'])}")
    print(f"HTML Body   : {bool(body['html'])}")
    print(f"URLs        : {len(urls)}")
    print(f"Attachments : {len(attachments)}")

    print("\n=== EXTRACTED URLS ===")
    for item in urls:
        print(f"[{item['source']}] {item['url']}")
        if item.get("text"):
            print(f"  Display text: {item['text'].strip()}")

    print("\n=== ATTACHMENTS ===")
    for attachment in attachments:
        print(f"Filename : {attachment['filename']}")
        print(f"MIME Type: {attachment['content_type']}")
        print(f"Size     : {attachment['size_bytes']} bytes")
        print(f"SHA-256  : {attachment['sha256']}")
        print()

    print(f"\n[+] Investigation report saved: {report_path}")


if __name__ == "__main__":
    main()
