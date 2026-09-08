"""Git services module for GitKraken Web.
Handles repository discovery, status, commit log parsing, diffs, layoutGraph calculation, and git actions.
1:1 Desktop Parity with authentic GitKraken mathematical lane allocation.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

GRAPH_COLOR_COUNT = 8


def run_git(cmd: List[str], cwd: str, check: bool = False) -> str:
    """Run a git command safely and return utf-8 stdout."""
    try:
        proc = subprocess.run(
            ["git", "-C", cwd] + cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=check,
        )
        return proc.stdout
    except subprocess.CalledProcessError as err:
        output = (err.stdout or "") + (err.stderr or "")
        raise RuntimeError(output.strip() or f"Git command failed: {' '.join(cmd)}") from err


def resolve_git_root(input_path: str) -> Optional[str]:
    """Resolve the root of a git repository from user input or common search paths."""
    clean_input = input_path.strip()
    candidates = [
        clean_input,
        f"/Volumes/Razer/code/{clean_input}",
        f"{os.path.expanduser('~')}/code/{clean_input}",
        f"{os.path.expanduser('~')}/{clean_input}",
        f"{os.path.expanduser('~')}/Desktop/{clean_input}",
        os.getcwd(),
        str(Path(__file__).resolve().parent),
    ]

    for candidate in candidates:
        try:
            p = Path(candidate).expanduser().resolve()
            if p.exists():
                out = subprocess.run(
                    ["git", "-C", str(p), "rev-parse", "--show-toplevel"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                if out.returncode == 0 and out.stdout.strip():
                    return out.stdout.strip()
        except Exception:
            continue
    return None


def scan_recent_repos() -> List[Dict[str, str]]:
    """Scan common developer directories for git repositories."""
    search_dirs = [
        "/Volumes/Razer/code",
        f"{os.path.expanduser('~')}/code",
        f"{os.path.expanduser('~')}/Projects",
        f"{os.path.expanduser('~')}/Desktop",
        f"{os.path.expanduser('~')}/Documents",
        str(Path(__file__).resolve().parent.parent),
    ]

    repos: List[Dict[str, str]] = []
    seen: set[str] = set()

    # Always include current repo
    curr = resolve_git_root(os.getcwd())
    if curr:
        seen.add(curr)
        repos.append({
            "name": Path(curr).name,
            "path": curr,
            "current": True,
        })

    for base_str in search_dirs:
        base = Path(base_str)
        if not base.is_dir():
            continue
        try:
            for item in base.iterdir():
                if item.is_dir() and not item.name.startswith("."):
                    git_dir = item / ".git"
                    if git_dir.exists() and str(item.resolve()) not in seen:
                        resolved = str(item.resolve())
                        seen.add(resolved)
                        repos.append({
                            "name": item.name,
                            "path": resolved,
                            "current": False,
                        })
                        if len(repos) >= 25:
                            break
        except (PermissionError, OSError):
            continue

    return repos


def get_author_avatar(name: str, email: str) -> str:
    """Resolve author avatar url using GitHub usernames or Gravatar."""
    clean_email = (email or "").strip().lower()

    # 1. GitHub noreply email format: 123456+username@users.noreply.github.com
    gh_match = re.match(r"(\d+)\+([^@]+)@users\.noreply\.github\.com", clean_email)
    if gh_match:
        return f"https://avatars.githubusercontent.com/u/{gh_match.group(1)}?s=64"

    # 2. Plain username noreply: username@users.noreply.github.com
    gh_user_match = re.match(r"([^@]+)@users\.noreply\.github\.com", clean_email)
    if gh_user_match:
        return f"https://github.com/{gh_user_match.group(1)}.png?size=64"

    # 3. Known project aliases
    clean_name = (name or "").lower()
    if "duy2172003" in clean_email or "ngọc duy" in clean_name or "kaizer" in clean_name:
        return "https://avatars.githubusercontent.com/u/129088035?s=64"
    if "lamtiendung" in clean_email or "dưỡng" in clean_name:
        return "https://avatars.githubusercontent.com/u/130898963?s=64"

    # 4. Gravatar fallback with retro generator
    md5_hash = hashlib.md5(clean_email.encode("utf-8") if clean_email else b"dev").hexdigest()
    return f"https://www.gravatar.com/avatar/{md5_hash}?d=retro&s=64"


def format_relative_date(timestamp: int) -> str:
    """Format unix timestamp into human-readable relative string."""
    diff_sec = int(time.time()) - timestamp
    if diff_sec < 0:
        return "just now"
    diff_min = diff_sec // 60
    diff_hour = diff_min // 60
    diff_day = diff_hour // 24

    if diff_day == 0:
        if diff_hour == 0:
            if diff_min == 0:
                return "just now"
            return f"{diff_min}m ago"
        return f"{diff_hour}h ago"
    if diff_day == 1:
        return "yesterday"
    if diff_day < 7:
        return f"{diff_day} days ago"
    if diff_day < 14:
        return "a week ago"
    if diff_day < 30:
        return f"{diff_day // 7} weeks ago"
    if diff_day < 60:
        return "a month ago"
    return f"{diff_day // 30} months ago"


# ==============================================================================
# GitKraken 1:1 Lane Allocation and Graph Edge Routing Engine
# ==============================================================================
def shape_for(row: Dict[str, Any]) -> str:
    r_type = row.get("type", "commit")
    if r_type == "wip":
        return "wip"
    if r_type == "stash":
        return "stash"
    parents = row.get("parents", [])
    if len(parents) > 1:
        return "merge"
    if len(parents) == 0:
        return "root"
    return "commit"


def eg(columns_used: Dict[int, bool], has_pinned: bool = False) -> int:
    col = 1 if has_pinned else 0
    while columns_used.get(col, False):
        col += 1
    columns_used[col] = True
    return col


def layout_graph(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Exact port of @gk-web/graph layoutGraph algorithm."""
    columns_used: Dict[int, bool] = {}
    reserver_info: Dict[str, Dict[str, int]] = {}
    columns_to_free: Dict[str, List[int]] = {}
    has_merge_child: Dict[str, bool] = {}
    assigned_columns: Dict[str, int] = {}
    target_parent_columns: Dict[str, Dict[str, int]] = {}

    # Pass 1: Lane reservation sweep
    for index, row in enumerate(rows):
        sha = row["sha"]
        if sha in has_merge_child:
            del has_merge_child[sha]
        parents = row.get("parents", [])

        to_free = columns_to_free.get(sha, [])
        for col in to_free:
            columns_used.pop(col, None)

        if sha in reserver_info and "column" in reserver_info[sha]:
            col = reserver_info[sha]["column"]
            del reserver_info[sha]
        else:
            col = eg(columns_used, False)
        assigned_columns[sha] = col

        parent_col_map: Dict[str, int] = {}
        for m, p in enumerate(parents):
            if len(parents) > 1:
                has_merge_child[p] = True
            p_res = reserver_info.get(p)

            if m == 0 and p_res and "column" in p_res and p_res["column"] != col:
                free_list = columns_to_free.get(p, [])
                if p_res["column"] > col and not has_merge_child.get(p):
                    target_col = col
                    reserver_info[p] = {"column": col}
                    free_list.append(p_res["column"])
                else:
                    target_col = p_res["column"]
                    free_list.append(col)
                columns_to_free[p] = free_list
            elif not p_res or "column" not in p_res:
                target_col = col if m == 0 else eg(columns_used, False)
                reserver_info[p] = {"column": target_col}
            else:
                target_col = p_res["column"]
            parent_col_map[p] = target_col
        target_parent_columns[sha] = parent_col_map

    # Pass 2: Edge routing sweep
    active_edges: Dict[int, Dict[str, Any]] = {}
    laid_out: List[Dict[str, Any]] = []

    for index, row in enumerate(rows):
        sha = row["sha"]
        my_col = assigned_columns.get(sha, 0)
        my_color = my_col % GRAPH_COLOR_COUNT
        parents = row.get("parents", [])
        segments: List[Dict[str, Any]] = []
        next_active: Dict[int, Dict[str, Any]] = {}

        # 1. Incoming edges
        for lane_col, edge in active_edges.items():
            if edge["parentSha"] == sha:
                segments.append({
                    "fromLane": lane_col,
                    "toLane": my_col,
                    "color": edge["color"],
                    "startsAtNode": False,
                    "endsAtNode": True,
                })
            else:
                segments.append({
                    "fromLane": lane_col,
                    "toLane": lane_col,
                    "color": edge["color"],
                    "startsAtNode": False,
                    "endsAtNode": False,
                })
                next_active[lane_col] = edge

        # 2. Outgoing edges
        p_cols = target_parent_columns.get(sha, {})
        for m, p in enumerate(parents):
            target_col = p_cols.get(p, my_col)
            edge_color = target_col % GRAPH_COLOR_COUNT
            segments.append({
                "fromLane": my_col,
                "toLane": target_col,
                "color": edge_color,
                "startsAtNode": True,
                "endsAtNode": False,
            })
            next_active[target_col] = {"parentSha": p, "color": edge_color}

        active_edges = next_active
        laid_out.append({
            "row": row,
            "index": index,
            "lane": my_col,
            "color": my_color,
            "shape": shape_for(row),
            "segments": segments,
        })

    return laid_out


def get_repo_data(repo_path: str, limit: int = 1000, status_only: bool = False) -> Dict[str, Any]:
    """Retrieve full repository status, refs, branches, and commit log with complete UIGraphRow layout."""
    target_path = resolve_git_root(repo_path)
    if not target_path:
        raise ValueError(f"Directory not a valid git repository: {repo_path}")

    # 1. Status & current branch
    status_out = run_git(["status", "--porcelain=v1", "-b", "-uall"], target_path)
    status_lines = status_out.splitlines()
    branch_line = status_lines[0] if status_lines else ""
    current_branch = "main"

    m = re.match(r"^##\s+([^.\s]+)", branch_line)
    if m:
        current_branch = m.group(1)

    ahead = 0
    behind = 0
    ahead_match = re.search(r"ahead\s+(\d+)", branch_line)
    if ahead_match:
        ahead = int(ahead_match.group(1))
    behind_match = re.search(r"behind\s+(\d+)", branch_line)
    if behind_match:
        behind = int(behind_match.group(1))

    staged: List[Dict[str, Any]] = []
    unstaged: List[Dict[str, Any]] = []

    for line in status_lines[1:]:
        if len(line) < 3:
            continue
        x = line[0]
        y = line[1]
        file_path = line[3:].strip()
        if '"' in file_path and file_path.startswith('"') and file_path.endswith('"'):
            file_path = file_path[1:-1]

        if x != " " and x != "?" and file_path:
            status_type = "modified" if x == "M" else ("added" if x == "A" else "deleted")
            staged.append({"path": file_path, "status": status_type, "code": x, "staged": True})
        if y != " " and file_path:
            status_type = "modified" if y == "M" else ("untracked" if y == "?" else "deleted")
            unstaged.append({"path": file_path, "status": status_type, "code": y, "staged": False})

    is_clean = len(staged) == 0 and len(unstaged) == 0

    # 2. Local branches
    local_out = run_git(["branch", '--format=%(refname)|%(refname:short)|%(objectname)|%(HEAD)'], target_path)
    local_branches: List[Dict[str, Any]] = []
    for line in local_out.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) >= 4:
            full_name, name, sha, head = parts[0], parts[1], parts[2], parts[3]
            is_head = head == "*"
            local_branches.append({
                "id": f"ref-local-{name}",
                "fullName": full_name,
                "name": name,
                "type": "localBranch",
                "sha": sha,
                "isCurrent": is_head,
                "isCheckedOut": is_head,
            })

    # 3. Remote branches
    remote_out = run_git(["branch", "-r", '--format=%(refname)|%(refname:short)|%(objectname)'], target_path)
    remote_branches: List[Dict[str, Any]] = []
    for line in remote_out.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) >= 3:
            full_name, name, sha = parts[0], parts[1], parts[2]
            if name.endswith("/HEAD") or name == "origin":
                continue
            remote_branches.append({
                "id": f"ref-remote-{name}",
                "fullName": full_name,
                "name": name,
                "type": "remoteBranch",
                "sha": sha,
                "isCurrent": False,
                "isCheckedOut": False,
            })

    # 4. Remotes
    remotes_out = run_git(["remote", "-v"], target_path)
    remotes: List[Dict[str, str]] = []
    seen_remotes: set[str] = set()
    for line in remotes_out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            r_name, r_url = parts[0], parts[1]
            if r_name not in seen_remotes:
                seen_remotes.add(r_name)
                remotes.append({
                    "name": r_name,
                    "fetchUrl": r_url,
                    "pushUrl": r_url,
                    "provider": "github" if "github.com" in r_url else "gitlab",
                })

    # 5. Tags
    tags_out = run_git(["tag", '--format=%(refname)|%(refname:short)|%(objectname)'], target_path)
    tags: List[Dict[str, Any]] = []
    for line in tags_out.splitlines():
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) >= 3:
            tags.append({
                "id": f"ref-tag-{parts[1]}",
                "fullName": parts[0],
                "name": parts[1],
                "type": "tag",
                "sha": parts[2],
            })

    # 6. Stashes
    stash_out = run_git(["stash", "list", '--format=%gd|%H|%gs|%ct'], target_path)
    stashes: List[Dict[str, Any]] = []
    for idx, line in enumerate(stash_out.splitlines()):
        if not line.strip():
            continue
        parts = line.split("|")
        if len(parts) >= 4:
            stashes.append({
                "id": f"ref-stash-{idx}",
                "name": parts[0],
                "sha": parts[1],
                "message": parts[2],
                "createdAt": int(parts[3] or "0") * 1000,
                "index": idx,
            })

    # 7. Commit Log
    log_out = run_git(
        [
            "log",
            "--all",
            f"-n {limit}",
            "--date-order",
            '--format=%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%s%x1f%D',
        ],
        target_path,
    )

    raw_commits: List[Dict[str, Any]] = []
    for line in log_out.splitlines():
        if not line.strip():
            continue
        parts = line.split("\x1f")
        if len(parts) < 7:
            continue
        sha = parts[0]
        parents = [p for p in parts[1].split() if p]
        author_name = parts[2] or "Developer"
        author_email = parts[3] or ""
        timestamp = int(parts[4] or "0")
        summary = parts[5] or ""
        ref_str = parts[6] or ""

        refs: List[Dict[str, Any]] = []
        if ref_str:
            for item in [r.strip() for r in ref_str.split(",")]:
                if item.startswith("HEAD -> "):
                    refs.append({"type": "head", "name": item.replace("HEAD -> ", ""), "isHead": True})
                elif item.startswith("tag: "):
                    refs.append({"type": "tag", "name": item.replace("tag: ", "")})
                elif item.startswith("origin/"):
                    b_name = item.replace("origin/", "")
                    if b_name != "HEAD":
                        refs.append({"type": "remote", "name": b_name})
                elif item != "HEAD":
                    refs.append({"type": "head", "name": item})

        raw_commits.append({
            "sha": sha,
            "shortSha": sha[:7],
            "parents": parents,
            "author": {
                "name": author_name,
                "email": author_email,
                "avatarUrl": get_author_avatar(author_name, author_email),
            },
            "timestamp": timestamp,
            "relativeDate": format_relative_date(timestamp),
            "summary": summary,
            "refs": refs,
        })

    # Protocol rows for layout engine
    protocol_rows: List[Dict[str, Any]] = []
    if not is_clean:
        protocol_rows.append({
            "sha": "wip",
            "parents": [raw_commits[0]["sha"]] if raw_commits else [],
            "type": "wip",
            "summary": "WIP: Local Uncommitted Changes",
            "description": "",
            "author": {"name": "You", "email": "you@local"},
            "refs": [],
        })

    for c in raw_commits:
        protocol_rows.append({
            "sha": c["sha"],
            "parents": c["parents"],
            "type": "merge" if len(c["parents"]) > 1 else "commit",
            "summary": c["summary"],
            "description": "",
            "author": {"name": c["author"]["name"], "email": c["author"]["email"]},
            "refs": c["refs"],
        })

    # Calculate graph layout
    laid_out = layout_graph(protocol_rows)

    commit_map = {c["sha"]: c for c in raw_commits}
    rows: List[Dict[str, Any]] = []

    wip_stats = {"modified": 0, "added": 0, "deleted": 0, "renamed": 0}
    if not is_clean:
        try:
            status_uall = run_git(["status", "--porcelain", "-uall"], target_path)
            for line in status_uall.splitlines():
                if not line:
                    continue
                code = line[:2]
                if "?" in code or "A" in code:
                    wip_stats["added"] += 1
                elif "M" in code:
                    wip_stats["modified"] += 1
                elif "D" in code:
                    wip_stats["deleted"] += 1
                elif "R" in code:
                    wip_stats["renamed"] += 1
        except Exception:
            pass

    for index, item in enumerate(laid_out):
        r = item["row"]
        sha = r.get("sha", "")
        is_wip = r.get("type") == "wip" or sha.lower() == "wip"

        if is_wip:
            rows.append({
                "sha": "wip",
                "summary": "// WIP",
                "isWip": True,
                "lane": item["lane"],
                "color": item["color"],
                "shape": "wip",
                "segments": item["segments"],
                "incomingSegments": [],
                "outgoingSegments": [],
                "passThroughLanes": [],
                "diffStats": wip_stats,
                "filesModified": wip_stats["modified"],
                "filesAdded": wip_stats["added"],
                "filesDeleted": wip_stats["deleted"],
                "filesRenamed": wip_stats["renamed"],
                "date": int(time.time() * 1000),
                "author": {
                    "name": "You",
                    "email": "you@local",
                    "avatarUrl": get_author_avatar("You", "you@local"),
                },
            })
            continue

        c = commit_map.get(sha)
        if not c:
            raw_idx = index if is_clean else index - 1
            if 0 <= raw_idx < len(raw_commits):
                c = raw_commits[raw_idx]

        if c:
            rel_date = c["relativeDate"]
            rows.append({
                "sha": c["sha"],
                "summary": c["summary"],
                "lane": item["lane"],
                "color": item["color"],
                "shape": item["shape"],
                "segments": item["segments"],
                "isMerge": item["shape"] == "merge",
                "incomingSegments": [],
                "outgoingSegments": [],
                "passThroughLanes": [],
                "author": c["author"],
                "date": c["timestamp"] * 1000,
                "relativeDate": rel_date,
                "refs": c["refs"],
            })

    status_payload = {
        "isClean": is_clean,
        "ahead": ahead,
        "behind": behind,
        "staged": staged,
        "unstaged": unstaged,
        "untracked": [],
        "conflicted": [],
    }

    # Fast path: only return status + rows for polling (skip refs/branches computation)
    if status_only:
        return {
            "ok": True,
            "currentBranch": current_branch,
            "status": status_payload,
            "rows": rows,
        }

    return {
        "ok": True,
        "repoName": Path(target_path).name,
        "repoPath": target_path,
        "currentBranch": current_branch,
        "status": status_payload,
        "refs": {
            "local": local_branches,
            "remotes": remotes,
            "remoteBranches": remote_branches,
            "tags": tags,
            "stashes": stashes,
            "worktrees": [],
            "submodules": [],
        },
        "rows": rows,
        "commits": raw_commits,
    }


def get_commit_details(repo_path: str, sha: str, target_file: Optional[str] = None, all_files: bool = False) -> Dict[str, Any]:
    """Retrieve detailed metadata, changed files, and diff for a specific commit."""
    target_path = resolve_git_root(repo_path)
    if not target_path:
        raise ValueError(f"Directory not a valid git repository: {repo_path}")

    # Commit metadata
    info_out = run_git(["log", "-1", '--format=%H%x1f%P%x1f%an%x1f%ae%x1f%at%x1f%s%x1f%b', sha], target_path)
    parts = info_out.split("\x1f")
    if len(parts) < 7:
        raise ValueError(f"Commit not found: {sha}")

    full_sha = parts[0]
    parents_str = parts[1]
    author_name = parts[2] or "Developer"
    author_email = parts[3] or ""
    author_timestamp = int(parts[4] or "0")
    summary = parts[5] or ""
    body = parts[6].strip()

    parents = [{"sha": p, "shortSha": p[:7]} for p in parents_str.split() if p]

    # Changed files and numstats
    numstat_out = run_git(["diff-tree", "--no-commit-id", "--numstat", "-m", "--first-parent", "--root", "-r", sha], target_path)
    namestatus_out = run_git(["diff-tree", "--no-commit-id", "--name-status", "-m", "--first-parent", "--root", "-r", sha], target_path)

    numstat_lines = [l for l in numstat_out.splitlines() if l.strip()]
    namestatus_lines = [l for l in namestatus_out.splitlines() if l.strip()]

    files: List[Dict[str, Any]] = []
    added = 0
    modified = 0
    deleted = 0
    renamed = 0

    for idx, line in enumerate(namestatus_lines):
        ns_parts = line.split("\t")
        if not ns_parts or not ns_parts[0]:
            continue
        status_code = ns_parts[0]
        file_path = ns_parts[1] if len(ns_parts) > 1 else ""

        additions = 0
        deletions = 0
        if idx < len(numstat_lines):
            nums = numstat_lines[idx].split("\t")
            if len(nums) >= 2:
                additions = int(nums[0]) if nums[0].isdigit() else 0
                deletions = int(nums[1]) if nums[1].isdigit() else 0

        status = "modified"
        if status_code.startswith("A"):
            status = "added"
            added += 1
        elif status_code.startswith("D"):
            status = "deleted"
            deleted += 1
        elif status_code.startswith("R"):
            status = "renamed"
            renamed += 1
        else:
            modified += 1

        last_slash = file_path.rfind("/")
        dir_name = file_path[: last_slash + 1] if last_slash != -1 else ""
        name = file_path[last_slash + 1 :] if last_slash != -1 else file_path

        files.append({
            "path": file_path,
            "dir": dir_name,
            "name": name,
            "status": status,
            "statusCode": status_code,
            "additions": additions,
            "deletions": deletions,
        })

    # Optional full tree listing
    all_files_list: List[Dict[str, Any]] = []
    if all_files:
        try:
            tree_target = "HEAD" if sha.lower() == "wip" else sha
            tree_out = run_git(["ls-tree", "-r", "--name-only", tree_target], target_path)
            changed_map = {f["path"]: f for f in files}
            for f_path in tree_out.splitlines():
                f_path = f_path.strip()
                if not f_path:
                    continue
                if f_path in changed_map:
                    all_files_list.append(changed_map[f_path])
                else:
                    last_slash = f_path.rfind("/")
                    dir_name = f_path[: last_slash + 1] if last_slash != -1 else ""
                    name = f_path[last_slash + 1 :] if last_slash != -1 else f_path
                    all_files_list.append({
                        "path": f_path,
                        "dir": dir_name,
                        "name": name,
                        "status": "unchanged",
                        "statusCode": " ",
                        "additions": 0,
                        "deletions": 0,
                    })
        except Exception:
            all_files_list = []

    # Optional file diff
    diff_text = None
    if target_file:
        parent_sha = parents[0]["sha"] if parents else None
        if parent_sha:
            diff_text = run_git(["diff", parent_sha, sha, "--", target_file], target_path)
        else:
            diff_text = run_git(["show", sha, "--", target_file], target_path)

    return {
        "commit": {
            "sha": full_sha,
            "shortSha": full_sha[:7],
            "summary": summary,
            "body": body,
            "author": {
                "name": author_name,
                "email": author_email,
                "avatarUrl": get_author_avatar(author_name, author_email),
                "date": author_timestamp * 1000,
                "relativeDate": format_relative_date(author_timestamp),
            },
            "parents": parents,
            "stats": {
                "added": added,
                "modified": modified,
                "deleted": deleted,
                "renamed": renamed,
                "total": len(files),
            },
            "files": files,
            "allFiles": all_files_list,
            "diff": diff_text,
        }
    }


def get_file_diff(repo_path: str, file_path: str, sha: Optional[str] = None, staged: bool = False) -> str:
    """Get file diff either for working tree, staged index, or historical commit."""
    target_path = resolve_git_root(repo_path)
    if not target_path:
        raise ValueError(f"Directory not a valid git repository: {repo_path}")

    if sha and sha != "WIP":
        parents_out = run_git(["log", "-1", "--format=%P", sha], target_path).strip()
        parent = parents_out.split()[0] if parents_out else None
        if parent:
            return run_git(["diff", parent, sha, "--", file_path], target_path)
        return run_git(["show", sha, "--", file_path], target_path)

    if staged:
        return run_git(["diff", "--cached", "--", file_path], target_path)

    diff = run_git(["diff", "--", file_path], target_path)
    if not diff.strip():
        full_p = Path(target_path) / file_path
        if full_p.is_file():
            try:
                content = full_p.read_text(encoding="utf-8", errors="replace")
                lines = content.splitlines()
                header = f"--- /dev/null\n+++ b/{file_path}\n@@ -0,0 +1,{len(lines)} @@\n"
                body = "\n".join(f"+{l}" for l in lines)
                return header + body
            except Exception:
                pass
    return diff


def execute_action(repo_path: str, action: str, params: Dict[str, Any]) -> Dict[str, Any]:
    """Execute Git mutation actions (pull, push, checkout, branch, commit, stage, etc.)."""
    target_path = resolve_git_root(repo_path)
    if not target_path:
        raise ValueError(f"Directory not a valid git repository: {repo_path}")

    if action == "checkout":
        branch = params.get("branchName", "").strip()
        if not branch:
            raise ValueError("Branch name required")
        out = run_git(["checkout", branch], target_path, check=True)
        return {"ok": True, "output": out}

    if action == "create-branch":
        branch = params.get("branchName", "").strip()
        checkout = params.get("checkout", True)
        if not branch:
            raise ValueError("Branch name required")
        args = ["checkout", "-b", branch] if checkout else ["branch", branch]
        out = run_git(args, target_path, check=True)
        return {"ok": True, "output": out}

    if action == "pull":
        mode = params.get("mode", "ff")
        if mode == "fetch":
            out = run_git(["fetch", "--all", "--prune"], target_path, check=True)
            return {"ok": True, "output": out or "Fetched all remotes"}
        args = ["pull"]
        if mode == "rebase":
            args.append("--rebase")
        elif mode == "ff-only":
            args.append("--ff-only")
        out = run_git(args, target_path, check=True)
        return {"ok": True, "output": out or "Already up to date"}

    if action == "fetch":
        out = run_git(["fetch", "--all", "--prune"], target_path, check=True)
        return {"ok": True, "output": out}

    if action == "push":
        current_branch = run_git(["rev-parse", "--abbrev-ref", "HEAD"], target_path).strip()
        force = params.get("force", False)
        args = ["push", "origin", current_branch]
        if force:
            args.insert(1, "--force-with-lease")
        out = run_git(args, target_path, check=True)
        return {"ok": True, "output": out}

    if action == "stage":
        file_path = params.get("path")
        if file_path:
            out = run_git(["add", "--", file_path], target_path, check=True)
        else:
            out = run_git(["add", "-A"], target_path, check=True)
        return {"ok": True, "output": out}

    if action == "unstage":
        file_path = params.get("path")
        if file_path:
            out = run_git(["restore", "--staged", "--", file_path], target_path, check=True)
        else:
            out = run_git(["restore", "--staged", "."], target_path, check=True)
        return {"ok": True, "output": out}

    if action == "commit":
        summary = params.get("summary", "").strip()
        description = params.get("description", "").strip()
        amend = params.get("amend", False)
        if not summary and not amend:
            raise ValueError("Commit message summary cannot be empty")

        full_msg = f"{summary}\n\n{description}".strip() if description else summary
        args = ["commit"]
        if amend:
            args.append("--amend")
        if full_msg:
            args.extend(["-m", full_msg])
        out = run_git(args, target_path, check=True)
        return {"ok": True, "output": out}

    if action == "stash":
        message = params.get("message", "").strip()
        args = ["stash", "push"]
        if message:
            args.extend(["-m", message])
        out = run_git(args, target_path, check=True)
        return {"ok": True, "output": out}

    if action == "pop":
        out = run_git(["stash", "pop"], target_path, check=True)
        return {"ok": True, "output": out}

    if action == "terminal":
        cmd_str = params.get("command", "").strip()
        if not cmd_str:
            raise ValueError("Command cannot be empty")
        proc = subprocess.run(
            cmd_str,
            cwd=target_path,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        return {"ok": proc.returncode == 0, "output": proc.stdout, "exitCode": proc.returncode}

    raise ValueError(f"Unknown action: {action}")
