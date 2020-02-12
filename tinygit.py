import argparse
import collections
import configparser
import difflib
import enum
import fnmatch
import getpass
import hashlib
import os
import stat
import struct
import sys
import time
import zlib

from utils import http_request
from utils import read_file
from utils import scan_dir
from utils import write_file


IndexEntry = collections.namedtuple("IndexEntry", [
    "ctime_s", "ctime_n", "mtime_s", "mtime_n", "dev", "ino", "mode", "uid",
    "gid", "size", "sha1", "flags", "path"])


class ObjectType(enum.Enum):
    commit = 1
    tree = 2
    blob = 3


def get_ignore_paths():
    """Read .gitignore file and return list of patterns."""
    try:
        data = read_file(".gitignore").decode()
        paths = data.split("\n")
    except FileNotFoundError:
        paths = []

    ignore_paths = []
    for path in paths:
        path = path.strip()
        if path and not path.startswith("#"):
            path = os.path.relpath(path, ".")
            if os.path.isdir(path):
                ignore_paths.extend(scan_dir(path))
            else:
                ignore_paths.append(path)
    ignore_paths.extend(scan_dir(".git"))
    return ignore_paths


def get_user_info():
    config_path = os.path.join(".git", "config")
    config = configparser.ConfigParser()
    config.read(config_path)
    if "user" not in config:
        name = input("Username: ")
        email = input("Email: ")
        config["user"] = {"name": name, "email": email}
    else:
        name = config["user"]["name"]
        email = config["user"]["email"]
    return name, email


def extract_lines(data):
    lines = []
    i = 0
    while True:
        line_length = int(data[i:i + 4], 16)
        line = data[i + 4:i + line_length]
        lines.append(line)
        if line_length == 0:
            i += 4
        else:
            i += line_length
        if i >= len(data):
            break
    return lines


def build_lines(lines):
    result = []
    for line in lines:
        length_prefix = f"{len(line) + 5:04x}".encode()
        result.append(length_prefix + line + b"\n")
    result.append(b"0000")
    return b"".join(result)


def get_local_master_hash():
    """Get current commit hash of local master branch."""
    master_path = os.path.join(".git", "refs", "heads", "master")
    try:
        return read_file(master_path).decode().strip()
    except FileNotFoundError:
        return None


def get_remote_master_hash(git_url, username, password):
    """Get commit hash of remote master branch, return SHA-1 hex string or 
    None if no remote commits.
    """
    url = git_url + "/info/refs?service=git-receive-pack"
    response = http_request(url, username, password)
    lines = extract_lines(response)
    assert lines[0] == b"# service=git-receive-pack\n"
    assert lines[1] == b""
    if lines[2][:40] == b"0" * 40:
        return None
    master_sha1, master_ref = lines[2].split(b"\x00")[0].split()
    assert master_ref == b"refs/heads/master"
    assert len(master_sha1) == 40
    return master_sha1.decode()


def find_tree_object(tree_sha1):
    """Return set of hashes of all objects in this tree, including the hash
    of the tree itself.
    """
    objects = {tree_sha1}
    for mode, path, sha1 in read_tree(sha1=tree_sha1):
        if stat.S_ISDIR(mode):
            objects.update(find_tree_object(sha1))
        else:
            objects.add(sha1)
    return objects


def get_commit_objects(commit_sha1):
    """Return set of SHA-1 hashes of all objects in this commit."""
    objects = {commit_sha1}
    obj_type, data = read_object(commit_sha1)
    assert obj_type == "commit"
    lines = data.decode().splitlines()
    tree_sha1 = [l[5:45] for l in lines if l.startswith("tree ")][0]
    objects.update(find_tree_object(tree_sha1))
    parents = [l[7:47] for l in lines if l.startswith("parent ")]
    for parent in parents:
        objects.update(get_commit_objects(parent))
    return objects


def find_missing_objects(local_sha1, remote_sha1):
    """Return set of SHA-1 hashes of objects in local commit that are missing 
    at the remote (based on the given remote commit hash).
    """
    local_objects = get_commit_objects(local_sha1)
    if remote_sha1 is None:
        return local_objects
    remote_objects = get_commit_objects(remote_sha1)
    return local_objects - remote_objects


def read_object(sha1_prefix):
    """Read object with given SHA-1 prefix and return tuple of 
    (object_type, data_bytes), or raise ValueError if not found.
    """

    def find_object():
        if len(sha1_prefix) < 2:
            raise ValueError("hash prefix must be 2 or more characters")
        obj_dir = os.path.join(".git", "objects", sha1_prefix[:2])
        rest = sha1_prefix[2:]
        objects = [n for n in os.listdir(obj_dir) if n.startswith(rest)]
        if not objects:
            raise ValueError(f"object {sha1_prefix!r} not found")
        if len(objects) > 1:
            raise ValueError(f"multiple objects ({len(objects)}) with" +
                             f"prefix {sha1_prefix!r}")
        return os.path.join(obj_dir, objects[0])

    path = find_object()
    full_data = zlib.decompress(read_file(path))
    nul_index = full_data.index(b"\x00")
    header = full_data[:nul_index]
    obj_type, size = header.decode().split()
    size = int(size)
    data = full_data[nul_index + 1:]
    assert len(data) == size, f"expected size {size}, got {len(data)} bytes"
    return obj_type, data


def hash_object(data, obj_type, write=True):
    """Compute hash of object data of given type and write to object store if 
    'write' is True. Return SHA-1 object hash as hex string.
    """
    header = f"{obj_type} {len(data)}".encode()
    full_data = header + b"\x00" + data
    sha1 = hashlib.sha1(full_data).hexdigest()
    if write:
        path = os.path.join(".git", "objects", sha1[:2], sha1[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            write_file(path, zlib.compress(full_data))
    return sha1


def read_index():
    """Read git index file and return list of IndexEntry objects."""
    try:
        data = read_file(os.path.join(".git", "index"))
    except FileNotFoundError:
        return []
    digest = hashlib.sha1(data[:-20]).digest()
    assert digest == data[-20:], "invalid index checksum"
    signature, version, num_entries = struct.unpack("!4sLL", data[:12])
    assert signature == b"DIRC", f"invalid index signature {signature}"
    assert version == 2, f"unknown index version {version}"
    entry_data = data[12:-20]
    entries = []
    i = 0
    while 62 + i < len(entry_data):
        body_end = i + 62
        body = struct.unpack("!LLLLLLLLLL20sH", entry_data[i:body_end])
        path_end = entry_data.index(b"\x00", body_end)
        path = entry_data[body_end:path_end]
        entry = IndexEntry(*(body + (path.decode(),)))
        entries.append(entry)
        i += ((62 + len(path)) // 8 + 1) * 8
    assert len(entries) == num_entries
    return entries


def write_index(entries):
    """Write list of IndexEntry objects to git index file."""
    packed_entries = []
    for e in entries:
        body = struct.pack("!LLLLLLLLLL20sH",
                           e.ctime_s, e.ctime_n, e.mtime_s, e.mtime_n, e.dev,
                           e.ino, e.mode, e.uid, e.gid, e.size, e.sha1, e.flags)
        path = e.path.encode()
        length = ((62 + len(path)) // 8 + 1) * 8
        packed_entry = body + path + b"\x00" * (length - 62 - len(path))
        packed_entries.append(packed_entry)
    header = struct.pack("!4sLL", b"DIRC", 2, len(entries))
    data = header + b"".join(packed_entries)
    digest = hashlib.sha1(data).digest()
    all_data = data + digest
    write_file(os.path.join(".git", "index"), all_data)


def read_tree(sha1=None, data=None):
    """Read tree object with given SHA-1 or data, return list of 
    (mode, path, sha1) tuples.
    """
    if sha1 is not None:
        obj_type, data = read_object(sha1)
        assert obj_type == "tree"
    elif data is None:
        raise ValueError("must specify 'sha1' or 'data'")
    i = 0
    entries = []
    while True:
        end = data.find(b"\x00", i)
        if end == -1:
            break
        mode_str, path = data[i:end].decode().split()
        mode = int(mode_str, 8)
        digest = data[end + 1:end + 21]
        entries.append((mode, path, digest.hex()))
        i = end + 1 + 20
    return entries


def write_tree():
    """Write a tree object from the current index entries."""

    def write_tree_recursively(entries, i=0):
        entry_by_filename = {}
        entry_by_dirname = collections.defaultdict(list)
        for entry in entries:
            sep_path = entry.path.split(os.path.sep)
            name = sep_path[i]
            if i < len(sep_path) - 1:
                entry_by_dirname[name].append(entry)
            else:
                entry_by_filename[name] = entry

        tree_entries = []
        for filename, entry in entry_by_filename.items():
            mode_path = f"{entry.mode:06o} {filename}".encode()
            tree_entry = mode_path + b"\x00" + entry.sha1
            tree_entries.append(tree_entry)

        for dirname, entries in entry_by_dirname.items():
            mode_path = f"{stat.S_IFDIR:06o} {dirname}".encode()
            tree_sha1 = write_tree_recursively(entries, i + 1)
            tree_entry = mode_path + b"\x00" + bytes.fromhex(tree_sha1)
            tree_entries.append(tree_entry)
        return hash_object(b"".join(tree_entries), "tree")

    return write_tree_recursively(read_index())


def get_status():
    """Get status of working copy, return tuple of (changed, new, deleted)."""
    ignore = get_ignore_paths()
    paths = set()
    for path in scan_dir("."):
        if all([not fnmatch.fnmatch(path, pattern) for pattern in ignore]):
            paths.add(path)
    entries_by_path = {e.path: e for e in read_index()}
    entry_paths = set(entries_by_path.keys())

    changed = set()
    for p in paths & entry_paths:
        if (hash_object(read_file(p), "blob", write=False) !=
                entries_by_path[p].sha1.hex()):
            changed.add(p)
    new = paths - entry_paths
    deleted = entry_paths - paths
    return sorted(changed), sorted(new), sorted(deleted)


def encode_pack_object(obj):
    """Encode a single object for a pack file and return bytes."""
    obj_type, data = read_object(obj)
    type_num = ObjectType[obj_type].value
    size = len(data)
    byte = (type_num << 4) | (size & 0x0f)
    size >>= 4
    header = []
    while size:
        header.append(byte | 0x80)
        byte = size & 0x7f
        size >>= 7
    header.append(byte)
    return bytes(header) + zlib.compress(data)


def create_pack(objects):
    """Create pack file containing all objects in given set of hashes, 
    return data bytes of full pack file.
    """
    header = struct.pack("!4sLL", b"PACK", 2, len(objects))
    body = b"".join(encode_pack_object(o) for o in sorted(objects))
    contents = header + body
    sha1 = hashlib.sha1(contents).digest()
    data = contents + sha1
    return data


def init(repo):
    """Create directory for repo and initialize .git"""
    repo = os.path.abspath(repo)
    os.makedirs(repo, exist_ok=True)
    git = os.path.join(repo, ".git")
    os.makedirs(git, exist_ok=True)
    for name in ["objects", "refs", os.path.join("refs", "heads")]:
        os.makedirs(os.path.join(git, name), exist_ok=True)

    write_file(os.path.join(git, "HEAD"), b"ref: refs/heads/master")
    config = configparser.ConfigParser()
    config["core"] = {"repositoryformatversion": 0, "filemode": True,
                      "bare": False}
    with open(os.path.join(git, "config"), "w") as f:
        config.write(f)
    print(f"Initialized empty repository: {repo}")


def add(paths):
    """Add all file paths to git index."""
    ignore = get_ignore_paths()
    all_paths = []
    for path in paths:
        path = os.path.relpath(path, ".")
        if not os.path.isfile(path):
            all_paths.extend(scan_dir(path))
        else:
            all_paths.append(path)
    paths = []
    for path in all_paths:
        if all([not fnmatch.fnmatch(path, pattern) for pattern in ignore]):
            paths.append(path)

    all_entries = read_index()
    entries = [e for e in all_entries if e.path not in paths]
    for path in paths:
        sha1 = hash_object(read_file(path), "blob")
        st = os.stat(path)
        flag = len(path.encode())
        assert flag < (1 << 12)
        entry = IndexEntry(
            int(st.st_ctime), 0, int(st.st_mtime), 0, st.st_dev,
            st.st_ino, st.st_mode, st.st_uid, st.st_gid, st.st_size,
            bytes.fromhex(sha1), flag, path)
        entries.append(entry)
    entries.sort(key=lambda e: e.path)
    write_index(entries)


def commit(message):
    """Commit the current state of the index to master with given message.
    Return hash of commit object.
    """
    tree = write_tree()
    parent = get_local_master_hash()
    name, email = get_user_info()
    author_info = f"{name} <{email}>"
    timestamp = int(time.mktime(time.localtime()))
    utc_offset = -time.timezone
    author_time = (f"{timestamp} {'+' if utc_offset > 0 else '-'}" +
                   f"{abs(utc_offset) // 3600:02}" +
                   f"{(abs(utc_offset) // 60) % 60:02}")

    lines = ["tree " + tree]
    if parent:
        lines.append("parent " + parent)
    lines.append(f"author {author_info} {author_time}")
    lines.append(f"committer {author_info} {author_time}")
    lines.append("")
    lines.append(message)
    lines.append("")
    data = "\n".join(lines).encode()
    sha1 = hash_object(data, "commit")
    master_path = os.path.join(".git", "refs", "heads", "master")
    write_file(master_path, (sha1 + "\n").encode())
    print(f"committed to master: {sha1}")
    return sha1


def status():
    """Show status of working copy."""
    changed, new, deleted = get_status()
    if changed:
        print("changed files:")
        for path in changed:
            print("\t", path)
    if new:
        print("new files:")
        for path in new:
            print("\t", path)
    if deleted:
        print("deleted files:")
        for path in deleted:
            print("\t", path)
    # TODO: check if there are added files to commit
    if not (changed or new or deleted):
        print("clean working directory, nothing to commit")


def diff():
    """Show diff of files changed (between index and working copy)."""
    changed, _, _ = get_status()
    entries_by_path = {e.path: e for e in read_index()}
    for i, path in enumerate(changed):
        sha1 = entries_by_path[path].sha1.hex()
        obj_type, data = read_object(sha1)
        assert obj_type == "blob"
        index_lines = data.decode().splitlines()
        working_lines = read_file(path).decode().splitlines()
        diff_lines = difflib.unified_diff(
            index_lines, working_lines, f"{path} (index)",
            f"{path} (working copy)", lineterm="")
        for line in diff_lines:
            print(line)
        if i < len(changed) - 1:
            print("-" * 70)


def push(git_url, username=None, password=None):
    if username is None:
        username = input("Username: ")
    if password is None:
        password = getpass.getpass()

    local_sha1 = get_local_master_hash()
    remote_sha1 = get_remote_master_hash(git_url, username, password)
    missing = find_missing_objects(local_sha1, remote_sha1)
    if len(missing) == 0:
        print("everything up-to-date.")
        return remote_sha1, None

    print(f"updating remote master from {remote_sha1 or 'no commit'} to "
          f"{local_sha1} ({len(missing)} objects)")
    head = (f"{remote_sha1 or '0' * 40} {local_sha1} "
            f"refs/heads/master\x00 report-status").encode()
    lines = [head]
    data = build_lines(lines) + create_pack(missing)
    url = git_url + "/git-receive-pack"
    response = http_request(url, username, password, data=data)
    lines = extract_lines(response)
    assert len(lines) > 1, f"expect at least 2 lines, got {len(lines)}"
    assert lines[0] == b"unpack ok\n", \
        f"expected line 1 b'unpack ok', got: {lines[0]}"
    assert lines[1] == b"ok refs/heads/master\n", \
        f"expected line 2 b'ok, refs/heads/master\n', got {lines[1]}'"
    return remote_sha1, missing


def cat_file(mode, sha1_prefix):
    obj_type, data = read_object(sha1_prefix)
    if mode in ("commit", "tree", "blob"):
        if obj_type != mode:
            raise ValueError(f"expected object type {mode}, got {obj_type}.")
    elif mode == "size":
        print(len(data))
    elif mode == "type":
        print(obj_type)
    elif mode == "pretty":
        if obj_type in ("commit", "blob"):
            sys.stdout.buffer.write(data)
        elif obj_type == "tree":
            for mode, path, sha1 in read_tree(data=data):
                type_str = "tree" if stat.S_ISDIR(mode) else "blob"
                print(f"{mode:06o} {type_str} {sha1}\t{path}")
        else:
            assert False, f"unhandled object type {obj_type!r}"
    else:
        raise ValueError(f"unexpected mode {mode!r}")


def parse_command(args):
    if args.command == "add":
        add(args.paths)
    elif args.command == "commit":
        commit(args.message)
    elif args.command == "diff":
        diff()
    elif args.command == "init":
        init(args.repo)
    elif args.command == "status":
        status()
    elif args.command == "push":
        push(args.git_url, username=args.username, password=args.password)
    elif args.command == "cat-file":
        try:
            cat_file(args.mode, args.hash_prefix)
        except ValueError as error:
            print(error, file=sys.stderr)
            sys.exit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    sub_parsers = parser.add_subparsers(dest="command")
    sub_parsers.required = True

    sub_parser = sub_parsers.add_parser("init", help="initialize a new repo")
    sub_parser.add_argument("--repo", default=".",
                            help="directory name for new repo")

    sub_parser = sub_parsers.add_parser("add", help="add file(s) to index")
    sub_parser.add_argument("paths", nargs="+", help="path(s) of files to add")

    sub_parser = sub_parsers.add_parser("commit",
                                        help="commit current state of index to master branch")
    sub_parser.add_argument("-m", "--message", required=True,
                            help="text of commit message")

    sub_parser = sub_parsers.add_parser("diff",
                                        help="show diff of files changed (between index and working copy)")

    sub_parser = sub_parsers.add_parser("status",
                                        help="show status of working copy")

    sub_parser = sub_parsers.add_parser("push",
                                        help="push master branch to given git server URL")
    sub_parser.add_argument("--url", help="URL of git repo")
    sub_parser.add_argument("-p", "--password",
                            help="password to use for authentication")
    sub_parser.add_argument("-u", "--username",
                            help="username to use for authentication")

    sub_parser = sub_parsers.add_parser("cat-file",
                                        help="display content of object")
    cat_file_modes = ("commit", "tree", "blob", "size", "type", "pretty")
    sub_parser.add_argument("mode", choices=cat_file_modes,
                            help="object type or display mode")
    sub_parser.add_argument("hash_prefix", help="SHA-1 hash prefix of object")

    args = parser.parse_args()
    parse_command(args)
