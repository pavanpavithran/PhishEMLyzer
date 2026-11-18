# 01 - Email Parsing and Header Extraction


**Project:** SilphishScope — Automated Phishing Investigation Platform  
**Phase:** 1 — Email Forensics & CLI Analyzer  
**Component:** Email Parser  
**Language:** Python 3  
**Status:** Initial implementation

---

## 1. Objective and Scope

### 1.1 Objective

The objective of this module is to develop a Python-based email parser capable of extracting and organizing information from raw `.eml` files for subsequent phishing investigations.

Email analysis is an important part of Security Operations Center (SOC) investigations. Suspicious emails may contain indicators of phishing, sender impersonation, credential harvesting, malicious attachments, or social engineering.

Before an email can be assessed for malicious activity, its underlying structure and metadata must be extracted.

This module establishes the foundation for subsequent detection and threat intelligence capabilities within SilphishScope.

### 1.2 Scope

The initial implementation focuses on:

- Loading email messages from `.eml` files.
- Parsing raw email data using Python's standard library.
- Extracting email metadata, including sender, recipient, subject, and timestamps.
- Extracting all email headers while preserving duplicate fields.
- Displaying extracted information through a command-line interface (CLI).
- Handling basic file-related errors.

**Out of scope for this implementation:**

- Phishing detection and risk scoring.
- SPF, DKIM, and DMARC verification.
- URL reputation analysis.
- Attachment inspection.
- Threat intelligence enrichment.
- SIEM integration.

These capabilities will be implemented in subsequent development stages.

---

## 2. Understanding `.eml` Structure and MIME

### 2.1 What is an `.eml` file?

An `.eml` file stores an individual email message in a format based on the Internet Message Format defined in RFC 5322.

A typical email consists of two main components:

**Headers:** Contain metadata describing the message, including the sender, recipients, subject, date, message identifiers, and routing information.

**Body:** Contains the actual message content. Depending on the email's structure, the body may include plain text, HTML, or multiple MIME components.

A simplified example:

```text
From: "IT Support" <support@example.com>
To: employee@example.org
Subject: Password Reset Required
Date: Tue, 17 Nov 2026 10:30:00 +0000
Message-ID: <test123@example.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hello,

Your account requires a password reset.

Visit https://example.com/reset.
```

The blank line separating the headers from the body is significant. It marks the end of the header section and the beginning of the message body.

### 2.2 MIME

Multipurpose Internet Mail Extensions (MIME) extend the basic email format to support multiple content types, character encodings, and file attachments.

Common MIME content types include:

| MIME Type | Description |
|---|---|
| `text/plain` | Plain-text email content |
| `text/html` | HTML-formatted email content |
| `multipart/alternative` | Alternative representations of the same content |
| `multipart/mixed` | Multiple message parts, commonly including attachments |
| `application/pdf` | PDF document |
| `application/octet-stream` | Generic binary content |

Understanding MIME is particularly important for phishing investigations because suspicious content may appear in HTML message bodies, attachments, or encoded message parts.

### 2.3 Security Relevance

Email headers and MIME structures provide valuable forensic information.

For example:

- `From` identifies the sender address presented in the message.
- `Reply-To` specifies where replies should be directed.
- `Return-Path` commonly represents the envelope sender used for delivery-status messages.
- `Received` headers record information about the mail servers involved in delivery.
- `Authentication-Results` may contain SPF, DKIM, and DMARC results reported by a mail server.

Differences between certain header values may warrant further investigation.

However, **email headers are not inherently trustworthy**. Some header fields can be forged, and their reliability depends on the systems that generated them.

SilphishScope will treat extracted header information as evidence to be evaluated rather than automatically assuming its authenticity.

---

## 3. Python Libraries and Parser Design

### 3.1 Libraries Used

The initial parser uses Python's standard library.

| Library | Purpose |
|---|---|
| `email.parser.BytesParser` | Parses raw email data into structured message objects |
| `email.policy` | Controls how email messages are interpreted |
| `pathlib.Path` | Handles file paths and file validation |
| `argparse` | Processes command-line arguments |

Using standard-library components minimizes external dependencies and allows the parser to work locally without an internet connection.

### 3.2 Parser Architecture

The initial implementation separates the command-line interface from email-processing logic.

```text
silphishscope/
├── main.py
└── analyzer/
    ├── __init__.py
    ├── banner.py
    └── parser.py
```

**`main.py`**

Acts as the entry point of the application. It processes CLI arguments, invokes the parser, and displays results.

**`analyzer/parser.py`**

Contains functions responsible for loading and parsing `.eml` files, extracting metadata, and preserving headers.

**`analyzer/banner.py`**

Contains the application's ASCII banner and display functionality.

This separation makes the code easier to maintain, test, and extend as additional analysis modules are introduced.

### 3.3 Email Loading

The `load_email()` function accepts a path to an `.eml` file and returns a parsed email message.

```python
def load_email(file_path: str):
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Email file not found: {file_path}"
        )

    if path.suffix.lower() != ".eml":
        raise ValueError("Only .eml files are supported.")

    with path.open("rb") as file:
        message = BytesParser(
            policy=policy.default
        ).parse(file)

    return message
```

**Design decisions:**

1. **Binary file reading:** Email files may contain different character encodings and MIME-encoded content. Reading the raw bytes allows the email parser to handle these structures.

2. **`BytesParser`:** Provides standards-aware parsing of message headers and MIME structures.

3. **`policy.default`:** Uses Python's modern email message handling behavior.

4. **File validation:** Checks whether the supplied file exists and uses the `.eml` extension.

The `.eml` extension check is an input-format restriction, not a security verification mechanism. It does not establish that the file is safe or correctly formatted.

---

## 4. Metadata and Header Extraction

### 4.1 Metadata Extraction

The `extract_metadata()` function extracts selected header fields commonly used during email investigations.

```python
def extract_metadata(message):
    metadata = {
        "from": str(message.get("From", "")),
        "to": str(message.get("To", "")),
        "subject": str(message.get("Subject", "")),
        "date": str(message.get("Date", "")),
        "message_id": str(message.get("Message-ID", "")),
        "reply_to": str(message.get("Reply-To", "")),
        "return_path": str(message.get("Return-Path", "")),
    }

    return metadata
```

The function returns a dictionary containing the extracted fields.

| Field | Investigation Relevance |
|---|---|
| From | Identifies the displayed sender |
| To | Identifies intended recipients |
| Subject | Provides message context |
| Date | Records the sender-declared message date |
| Message-ID | Provides a message identifier |
| Reply-To | Identifies the requested reply destination |
| Return-Path | Provides envelope sender information when available |

Missing fields are represented by empty strings.

At this stage, extracted values are not evaluated for malicious behavior.

### 4.2 Header Extraction

The `extract_headers()` function preserves all headers using a list of dictionaries.

```python
def extract_headers(message):
    return [
        {"name": name, "value": str(value)}
        for name, value in message.raw_items()
    ]
```

This approach is important because email messages may contain repeated headers.

For example:

```text
Received: from mail2.example.com
Received: from mail1.example.com
```

Converting all headers into a conventional dictionary could overwrite or discard repeated fields.

By using a list, the application preserves the order and occurrence of headers, making the output more useful for later forensic analysis.

The `raw_items()` method retrieves header names and raw header values, which is useful for preserving source details. The implementation still converts the values to strings for display; this is not a byte-for-byte preservation of the original email.

### 4.3 Command-Line Interface

The initial CLI accepts a file path using the `-f` or `--file` argument.

Example:

```bash
python3 main.py --file samples/test.eml
```

The application:

1. Reads the specified email file.
2. Parses its structure.
3. Extracts selected metadata.
4. Extracts the complete header list.
5. Prints the results to the terminal.

The initial implementation does not modify the source email file.

---

## 5. Test Cases and Screenshots

### 5.1 Test Environment

| Component | Details |
|---|---|
| Operating System | *To be recorded* |
| Python Version | *To be recorded* |
| Application Version | SilphishScope v0.1 |
| Test Input | `samples/test.eml` |

### 5.2 Test Case 1 — Valid Email Parsing

**Objective:** Verify that the parser successfully processes a synthetically generated `.eml` file.

**Command:**

```bash
python3 main.py --file samples/test.eml
```

**Expected result:**

- The application loads the `.eml` file.
- Metadata fields are printed correctly.
- The complete header list is displayed.
- No exceptions occur.

**Actual result:** *Pending test execution.*

**Screenshot:**

*Insert screenshot of successful terminal output.*

```markdown
![Successful email parsing](images/01-successful-parsing.png)
```

### 5.3 Test Case 2 — Missing File

**Objective:** Verify error handling when a nonexistent file path is provided.

**Command:**

```bash
python3 main.py --file nonexistent.eml
```

**Expected result:**

The CLI displays an appropriate file-not-found error and exits without an unhandled traceback.

**Actual result:** *Pending test execution.*

### 5.4 Test Case 3 — Unsupported Extension

**Objective:** Verify rejection of unsupported file extensions.

**Command:**

```bash
python3 main.py --file samples/test.txt
```

**Expected result:**

If `samples/test.txt` exists, the program rejects it because its extension is not `.eml`.

**Actual result:** *Pending test execution.*

### 5.5 Test Case 4 — Duplicate Headers

**Objective:** Verify that repeated email headers are preserved.

**Procedure:**

Create a synthetic email containing multiple `Received` fields and analyze it using SilphishScope.

**Expected result:**

All `Received` fields appear in the CLI output without being overwritten.

**Actual result:** *Pending test execution.*

### 5.6 Test Summary

| Test Case | Expected Behavior | Status |
|---|---|---|
| Valid `.eml` file | Successfully parse and display headers | Not yet recorded |
| Missing file | Display file-not-found error | Not yet recorded |
| Unsupported extension | Reject unsupported extension | Not yet recorded |
| Duplicate headers | Preserve all header occurrences | Not yet recorded |

Test statuses should be updated after actual execution.

---

## 6. Limitations and Next Steps

### 6.1 Current Limitations

The initial parser has the following limitations:

**No phishing detection**

The application extracts information but does not determine whether an email is malicious.

**No body extraction**

Although the email is parsed, the current CLI does not extract or display plain-text and HTML message bodies.

**No URL extraction**

URLs embedded in email content are not currently extracted or analyzed.

**No attachment inspection**

Attachments are not identified, hashed, or inspected.

**Limited input validation**

The parser verifies file existence and extension but does not yet enforce file size limits, comprehensively validate malformed content, or handle every possible parsing defect.

**No persistent reports**

Extracted data is displayed in the terminal but is not yet saved to a structured JSON investigation report.

**No authentication verification**

Authentication-related headers can be extracted as text but are not independently validated. A header claiming that SPF, DKIM, or DMARC passed does not establish that the claim is trustworthy.

### 6.2 Next Steps

The remaining Phase 1 development tasks are:

- Implement extraction of plain-text and HTML email bodies.
- Support multipart MIME messages.
- Extract URLs from message content.
- Identify email attachments and calculate SHA-256 hashes.
- Generate structured JSON investigation reports.
- Create unit tests covering expected and malformed inputs.

Subsequent project phases will introduce detection rules, risk scoring, threat intelligence integrations, a SOC investigation dashboard, and Wazuh SIEM integration.

### 6.3 Conclusion

The initial implementation of SilphishScope establishes a modular foundation for email forensic analysis.

The parser uses Python's standard email-handling libraries to load `.eml` files, retrieve selected metadata, and preserve complete header information