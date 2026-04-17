import email
import json

def parse_eml(file_path):
    with open(file_path, "rb") as f:
        msg = email.message_from_bytes(f.read())

    email_data = {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "date": msg.get("Date"),
        "body": "",
        "attachments": []
    }

    # Extract body + attachments
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition"))

            # Get body
            if content_type == "text/plain" and "attachment" not in content_disposition:
                email_data["body"] = part.get_payload(decode=True).decode(errors="ignore")

            # Get attachments
            if "attachment" in content_disposition:
                filename = part.get_filename()
                if filename:
                    email_data["attachments"].append(filename)
    else:
        email_data["body"] = msg.get_payload(decode=True).decode(errors="ignore")

    return email_data


# Run parser
data = parse_eml("email.eml")

# Save JSON
with open("output.json", "w") as f:
    json.dump(data, f, indent=4)

print("Done ✔")