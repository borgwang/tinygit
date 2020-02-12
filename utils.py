import os

import requests


def read_file(path):
    """Read contents of files at given path as bytes."""
    with open(path, "rb") as f:
        return f.read()


def write_file(path, data):
    """Write data bytes to file at given path."""
    with open(path, "wb") as f:
        f.write(data)


def scan_dir(directory):
    """Return all file paths in the given directory."""
    paths = []
    for dirpath, _, filenames in os.walk(directory):
        for filename in filenames:
            path = os.path.relpath(os.path.join(dirpath, filename), ".")
            paths.append(path)
    return paths


def http_request(url, username, password, data=None):
    request_method = requests.get if data is None else requests.post
    response = request_method(url, auth=(username, password), data=data)
    response.raise_for_status()
    return response.content
