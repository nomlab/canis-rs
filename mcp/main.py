from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource, Prompt, PromptArgument, GetPromptResult, PromptMessage
from mcp.shared.exceptions import McpError

import json
from typing import Sequence

import sqlite3
import subprocess
from contextlib import contextmanager
from urllib.parse import urlparse
from pathlib import Path

import asyncio
import sys

class CanisServer:
    def __init__(self, db_path: str):
        self.db_path = db_path

    @contextmanager
    def _connect(self):
        con = sqlite3.connect(self.db_path)
        con.row_factory = sqlite3.Row
        try:
            yield con
        finally:
            con.close()

    def create_hash(self, filepath: str) -> str:
        """Create hash from specified file"""
        hash = subprocess.run(["sha256sum", filepath], capture_output=True, text=True).stdout
        return hash

    def search_target_from_log(self, target: str) -> str:
        """Search for specified file path or hash value in DB"""
        uri = self._normalize_to_uri(target)

        with self._connect() as con:
            rows = con.execute(
                """
                SELECT created_at, uri, hash
                FROM Digest
                WHERE (:uri IS NOT NULL AND uri = :uri) OR hash = :hash
                ORDER BY created_at DESC
                """,
                {"uri": uri, "hash": target},
            ).fetchall()

        if not rows:
            return "Target not found in hash log."

        return "\n".join(
            f"{row['created_at']}  {row['uri']}  {row['hash']}"
            for row in rows
        )

    def create_daily_log_file(self, day: str, path: str) -> str:
        """Fetch records for a specific date from DB and save to file"""
        with self._connect() as con:
            rows = con.execute(
                """
                SELECT created_at, uri, hash
                FROM Digest
                WHERE DATE(created_at) = DATE(:day)
                ORDER BY created_at
                """,
                {"day": day},
            ).fetchall()

        with open(path, "w") as f:
            for row in rows:
                print(f"{row['created_at']},{row['uri']},{row['hash']}", file=f)

        return f"Hash log saved to: {path}"

    def get_directory_tree(self, directory: str) -> str:
        """Return a tree of operated files under the specified directory."""

        uri = self._normalize_to_uri(directory)
        if uri is None:
            raise ValueError("Directory must be an absolute path or URI.")

        with self._connect() as con:
            rows = con.execute(
                """
                SELECT DISTINCT uri
                FROM Operation
                WHERE uri LIKE ? || '%'
                ORDER BY uri
                """,
                (uri,),
            ).fetchall()

        root_path = Path(urlparse(uri).path)

        root = {
            "name": root_path.name,
            "path": uri,
            "files": [],
            "children": {}
        }

        for row in rows:
            file_uri = row["uri"]
            file_path = Path(urlparse(file_uri).path)

            try:
                rel = file_path.relative_to(root_path)
            except ValueError:
                continue

            node = root
            current_path = root_path

            for dirname in rel.parts[:-1]:
                current_path /= dirname

                node = node["children"].setdefault(
                    dirname,
                    {
                        "name": dirname,
                        "path": current_path.as_uri(),
                        "files": [],
                        "children": {}
                    }
                )

            node["files"].append(rel.name)

        def convert(node):
            return {
                "name": node["name"],
                "path": node["path"],
                "files": sorted(node["files"]),
                "children": {
                    name: convert(child)
                    for name, child in sorted(node["children"].items())
                }
            }

        return json.dumps(convert(root), indent=2, ensure_ascii=False)

    def save_directory_description(self, output_path: str, tree_json: str) -> str:
        """
        Save generated directory descriptions.

        Arguments
        ---------
        output_path:
            Destination JSON file.

        tree:
            The COMPLETE directory tree as a JSON object.

        The value of `tree` MUST be a JSON object, NOT a JSON string.

        Correct example:

        {
        "path": "file:///home/otsuki/research",
        "description": "...",
        "children": {
            "paper": {
            "path": "...",
            "description": "...",
            "children": {}
            }
        }
        }

        Incorrect example (DO NOT DO THIS):

        {
        "tree": "{\"path\":\"...\"}"
        }

        The tool writes the tree to the output file and merges existing descriptions.
        """

        try:
            tree = json.loads(tree_json)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON: {e}")

        output = Path(output_path)

        if output.exists():
            try:
                with output.open("r", encoding="utf-8") as f:
                    old_tree = json.load(f)
            except (json.JSONDecodeError, OSError):
                old_tree = None
        else:
            old_tree = None

        def merge(old: dict | None, new: dict) -> dict:
            result = {
                "path": new["path"],
                "description": new.get("description", ""),
                "children": {}
            }

            if old is not None:
                old_desc = old.get("description", "")
                if result["description"].strip() == "":
                    result["description"] = old_desc

            old_children = old.get("children", {}) if old else {}

            for name, child in new.get("children", {}).items():
                result["children"][name] = merge(
                    old_children.get(name),
                    child
                )

            return result

        merged = merge(old_tree, tree)

        output.parent.mkdir(parents=True, exist_ok=True)

        with output.open("w", encoding="utf-8") as f:
            json.dump(merged, f, indent=2, ensure_ascii=False)

        return (
            f"Successfully saved directory descriptions to "
            f"'{output.resolve()}'."
        )

    @staticmethod
    def _normalize_to_uri(target: str) -> str:
        parsed = urlparse(target)
        if parsed.scheme:
            return target
        p = Path(target)
        if p.is_absolute():
            return p.as_uri()
        return None

async def serve(hashlog: str) -> None:
    server = Server("canis-mcp")
    canis_server = CanisServer(hashlog)

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        """List available canis tools."""
        return [
            Tool(
                name="create_hash",
                description="Create a hash from specified file",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "filepath": {
                            "type": "string",
                            "description": "Filepath specified by the user.",
                        }
                    },
                    "required": ["filepath"],
                }
            ),
            Tool(
                name="search_target_from_log",
                description="Search for specified file or hash value in hash log",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Filepath or hash value specified by the user.",
                        }
                    },
                    "required": ["target",],
                }
            ),
            Tool(
                name="create_daily_log_file",
                description="Create a hash from logs obtained on a specific date",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "day": {
                            "type": "string",
                            "description": "Date specified by the user. The format must be '2025-06-01'.",
                        },
                        "path":{
                            "type":"string",
                            "description": "The path to the file where hash logs for a specific date are stored. If not specified by the user, the file will be automatically named using the format daily_hash_<day>.log"
                        }
                    },
                    "required": ["day","path"],
                }
            ),
            Tool(
                name="get_directory_tree",
                description=(
                    "Return the operated directory tree under the specified directory. "
                    "Use this tool first when generating directory descriptions. "
                    "Only call more detailed tools if filenames and directory structure are insufficient."
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "directory": {
                            "type": "string",
                            "description": "Directory path or URI."
                        }
                    },
                    "required": ["directory"],
                }
            ),
            Tool(
                name="save_directory_description",
                description = (
                    "A JSON string representing the complete directory tree.\n\n"
                    "The JSON must exactly preserve the structure returned by "
                    "get_directory_tree.\n"
                    "Only fill the description fields.\n"
                    "Do not remove 'path'.\n"
                    "Do not remove 'files'.\n"
                    "Do not convert children into an array.\n"
                    "Keep children as an object.\n\n"
                    "Example:\n"
                    "{\"path\":\"file:///...\",\"description\":\"...\",\"children\":{}}"
                ),
                inputSchema={
                    "type": "object",
                    "properties": {
                        "output_path": {
                            "type": "string",
                            "description": "Destination JSON file."
                        },
                        "tree_json": {
                            "type": "string",
                            "description": (
                                "Directory description tree as a JSON string."
                            )
                        }
                    },
                    "required": [
                        "output_path",
                        "tree_json"
                    ]
                }
            )
        ]

    @server.call_tool()
    async def call_tool(
        name: str, arguments: dict
    ) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
        """Handle tool calls for canis queries."""
        try:
            match name:
                case "create_hash":
                    filepath = arguments.get("filepath")
                    if not filepath:
                        raise ValueError("Missing required argument: filepath")

                    result = canis_server.create_hash(filepath)

                case "search_target_from_log":
                    target = arguments.get("target")
                    if not target:
                        raise ValueError("Missing required argument: target")

                    result = canis_server.search_target_from_log(target)

                case "create_daily_log_file":
                    day = arguments.get("day")
                    path = arguments.get("path")
                    if not day:
                        raise ValueError("Missing required argument: day")
                    if not path:
                        raise ValueError("Missing required argument: path")

                    result = canis_server.create_daily_log_file(day, path)

                case "get_directory_tree":
                    directory = arguments.get("directory")
                    if not directory:
                        raise ValueError("Missing required argument: directory")

                    result = canis_server.get_directory_tree(directory)

                case "save_directory_description":
                    output_path = arguments.get("output_path")
                    tree_json = arguments.get("tree_json")

                    if not output_path:
                        raise ValueError(
                            "Missing required argument: output_path"
                        )

                    if tree_json is None:
                        raise ValueError(
                            "Missing required argument: tree_json"
                        )

                    result = canis_server.save_directory_description(
                        output_path,
                        tree_json
                    )

            return [
                TextContent(type="text", text=result.strip())
            ]

        except Exception as e:
            raise ValueError(f"Error processing canis-mcp query: {str(e)}")

    options = server.create_initialization_options()
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, options)

def main():
    if len(sys.argv) < 2:
        print("Usage: python main.py <db_path>")
        sys.exit(1)
    db_path = sys.argv[1]
    asyncio.run(serve(db_path))


if __name__ == "__main__":
    main()
