import os
import zipfile


def extract_zip(zip_path: str, extract_to: str) -> None:
    if not zipfile.is_zipfile(zip_path):
        raise Exception("Invalid ZIP file")

    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(extract_to)


def find_dockerfile_path(base_path: str) -> str:
    for root, _, files in os.walk(base_path):
        if "Dockerfile" in files:
            return root
    raise Exception("Dockerfile not found")
