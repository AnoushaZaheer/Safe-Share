import json
from pathlib import Path
import shutil

def load_config():
    """
    Load configuration from config/config.json
    """

    config_path = Path(__file__).parent.parent / "config" / "config.json"

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found:\n{config_path}")

    with open(config_path, "r", encoding="utf-8") as file:
        config = json.load(file)

    return config


def copy_project(config):
    """
    Copy the source project to the destination.
    """

    source = Path(config["source"])
    destination = Path(config["destination"])

    if not source.exists():
        raise FileNotFoundError(f"Source project not found:\n{source}")

    # Delete old copy
    if destination.exists():
        print("🗑 Removing old project...")
        shutil.rmtree(destination)

    print("📂 Copying project...")

    shutil.copytree(
        source,
        destination,
        ignore=shutil.ignore_patterns(*config["ignore"])
    )

    print("✅ Project copied successfully.")


def sanitize(config):
    """
    Replace sensitive text inside supported files.
    """

    destination = Path(config["destination"])

    files_modified = 0
    replacements = 0

    print("🧹 Sanitizing files...")

    for file in destination.rglob("*"):

        if not file.is_file():
            continue

        if file.suffix.lower() not in config["extensions"]:
            continue

        try:

            content = file.read_text(encoding="utf-8")

            original = content

            for old, new in config["replace"].items():

                count = content.count(old)

                if count > 0:
                    replacements += count
                    content = content.replace(old, new)

            if content != original:
                file.write_text(content, encoding="utf-8")
                files_modified += 1

        except Exception:
            # Ignore binary/unreadable files
            pass

    print(f"✅ {files_modified} file(s) sanitized.")
    print(f"✅ {replacements} replacement(s) made.")