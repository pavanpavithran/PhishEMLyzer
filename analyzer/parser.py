from email import policy
from email.parser import BytesHeaderParser, BytesParser
from pathlib import Path

def load_email(file_path: str):
  
  path = Path(file_path)
  
  if not path.is_file():
    raise FileNotFoundError(
      f"Email file not found in {file_path}"
    )

  if path.suffix.lower() != ".eml":
    raise ValueError(
      "Only .eml files are supported"
    )

  with path.open("rb") as file:
    message = BytesParser(
      policy=policy.default
    ).parse(file)

    return message
    
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


def extract_headers(message):

    return [
        {"name": name, "value": str(value)}
        for name, value in message.raw_items()
    ]
