import json
import os
from datetime import date

def load_services():
    with open(os.path.join("data", "services.json"), "r", encoding="utf-8") as f:
        return json.load(f)

def send_petitions(selected_ids, result_map, user_name="John Doe"):
    """
    Generates and prints petitions for selected services.
    Supports both known services and DuckDuckGo dynamic results.
    """
    services = load_services()

    for site_id in selected_ids:
        if site_id.startswith("duck_"):
            url = result_map.get(site_id, "[URL not found]")

            petition = f"""
To whom it may concern,

I am requesting the removal of the following URL that appears in search results for my name:

→ URL: {url}

This request is submitted on {date.today().strftime('%B %d, %Y')}. Please process it in accordance with applicable privacy regulations.

Sincerely,  
{user_name}
"""
            print(f"\n📄 Petition for DuckDuckGo Result ({site_id}):")
            print(petition)

        else:
            service = next((s for s in services if s["id"] == site_id), None)
            if not service:
                print(f"[WARN] Service ID '{site_id}' not found in services.json.")
                continue

            petition_template = service.get("petition_template", "")
            petition = petition_template.format(
                today=date.today().strftime('%B %d, %Y'),
                site_name=service.get("name", "The Site")
            ).replace("[Your Name]", user_name).replace("[Your Full Name]", user_name)

            print(f"\n📄 Petition for {service['name']}:")
            print(petition)
