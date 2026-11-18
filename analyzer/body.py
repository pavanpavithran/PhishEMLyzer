def extract_body(message):
    
    plain_parts = []
    html_parts = []

    for part in message.walk():
        # Skip multipart containers
        if part.is_multipart():
            continue

        # Skip attachments, including inline files with names
        if part.get_content_disposition() == "attachment":
            continue

        if part.get_filename():
            continue

        content_type = part.get_content_type()

        if content_type not in ("text/plain", "text/html"):
            continue

        try:
            content = part.get_content()
        except (UnicodeError, LookupError, ValueError):
            continue

        if not isinstance(content, str):
            continue

        if content_type == "text/plain":
            plain_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(content)

    return {
        "plain": "\n".join(plain_parts),
        "html": "\n".join(html_parts),
    }
