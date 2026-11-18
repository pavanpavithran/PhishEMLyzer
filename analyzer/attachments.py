import hashlib


def extract_attachments(message):
    """
    Identify attachment-like MIME parts and extract
    metadata without writing files to disk.
    """

    attachments = []

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()
        disposition = part.get_content_disposition()

        if disposition != "attachment" and not filename:
            continue

        payload = part.get_payload(decode=True)

        if not isinstance(payload, bytes):
            payload = b""

        attachment = {
            "filename": filename,
            "content_type": part.get_content_type(),
            "disposition": disposition,
            "size_bytes": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

        attachments.append(attachment)

    return attachments
