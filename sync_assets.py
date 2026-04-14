import os
import base64
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

def upload_to_github():
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN not found in .env")
        return

    owner = "Ravisankar04"
    repo = "lumina-security-auditor"
    local_path = Path("create_an_image_202604121238.png")
    repo_path = "hero.png"
    
    if not local_path.exists():
        print(f"Error: Local file {local_path} not found")
        return

    # 1. Get the current file SHA (if it exists) to update it
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{repo_path}"
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    sha = None
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        sha = response.json()["sha"]
        print(f"Found existing {repo_path} with SHA {sha}")

    # 2. Upload the file
    with open(local_path, "rb") as f:
        content = base64.b64encode(f.read()).decode("utf-8")

    data = {
        "message": "Upload high-resolution hero image",
        "content": content,
        "branch": "main"
    }
    if sha:
        data["sha"] = sha

    print(f"Uploading {local_path} to {owner}/{repo}/{repo_path}...")
    response = requests.put(url, headers=headers, json=data)
    
    if response.status_code in [200, 201]:
        print("Success! Image uploaded to GitHub.")
    else:
        print(f"Error: Failed to upload. Status: {response.status_code}")
        print(response.text)

if __name__ == "__main__":
    upload_to_github()
