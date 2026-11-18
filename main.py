
import argparse

from analyzer.banner import display_banner
from analyzer.parser import (
    load_email,
    extract_metadata,
    extract_headers,
)


def main():
    #display_banner()
    parser = argparse.ArgumentParser(
        description="SilphishScope - Email Forensics Analyzer"
    )

    parser.add_argument(
        "-f", "--file",
        required=True,
        help="Path to the .eml file"
    )

    args = parser.parse_args()

    print("\nPhishScope v0.1")
    print("Loading email...\n")

    try:
        message = load_email(args.file)
        metadata = extract_metadata(message)
        headers = extract_headers(message)

    except (FileNotFoundError, ValueError, OSError) as error:
        parser.error(str(error))

    print("=== EMAIL METADATA ===")

    for key, value in metadata.items():
        print(f"{key.upper():15}: {value}")

    print("\n=== EMAIL HEADERS ===")

    for header in headers:
        print(f"{header['name']}: {header['value']}")


if __name__ == "__main__":
    main()
