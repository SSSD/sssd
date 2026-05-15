#!/usr/bin/env python3

import argparse
import re
import subprocess
import sys
import pypandoc


class ReleaseNote:
    """Represents a category of release notes."""

    def __init__(self, tag, title):
        self.tag = tag
        self.title = title

    def findall(self, git_log):
        """Extract all notes for this tag from the git log."""
        # Pattern matches :tag: followed by content until empty line or next tag
        pattern = rf"^ *:{self.tag}:((?:(?!(?:^ *:\w+:| *$)).*\n)+)"
        matches = re.findall(pattern, git_log, re.MULTILINE)

        if not matches:
            return []

        notes = []
        for match in matches:
            # Join multiline notes, preserving markdown formatting
            note = " ".join([line.strip() for line in match.split("\n")])
            notes.append(f"* {note}")

        return notes

    def generate(self, git_log):
        notes = self.findall(git_log)
        if not notes:
            return ""

        output = f"### {self.title}\n\n"
        output += "\n".join(notes)
        return output


class ReleaseNotesGenerator:
    """Generate release notes from git commit messages."""

    def __init__(self, from_ref, to_ref, version):
        self.from_ref = from_ref
        self.to_ref = to_ref
        self.version = version

        self.project_name = "SSSD"
        self.categories = [
            ReleaseNote("relnote", "General information"),
            ReleaseNote("feature", "New features"),
            ReleaseNote("fixes", "Important fixes"),
            ReleaseNote("packaging", "Packaging changes"),
            ReleaseNote("config", "Configuration changes"),
        ]

    def get_git_log(self, from_ref, to_ref):
        """Get git log between two references."""
        result = subprocess.run(
            ["git", "log", "--pretty=medium", "--no-abbrev-commit", f"{from_ref}..{to_ref}"],
            capture_output=True,
            text=True,
            check=True,
        )

        return result.stdout

    def generate(self):
        """Generate release notes in markdown."""
        git_log = self.get_git_log(self.from_ref, self.to_ref)
        output = f"# {self.project_name} {self.version} Release Notes\n"
        output += "\n"
        output += "## Highlights\n"

        # Generate sections for each category
        for category in self.categories:
            notes = category.generate(git_log)
            if notes:
                output += "\n"
                output += notes
                output += "\n"

        return output.strip()


def main():
    parser = argparse.ArgumentParser(
        description="Generate release notes from git commit messages"
    )
    parser.add_argument(
        "--from", type=str, required=True, dest="from_ref", help="Start point reference"
    )
    parser.add_argument(
        "--to",
        type=str,
        default="HEAD",
        dest="to_ref",
        help="End point reference (default: HEAD)",
    )
    parser.add_argument(
        "--version", type=str, required=True, help="New release version"
    )
    parser.add_argument(
        "--format",
        type=str,
        choices=["md", "rst"],
        default="md",
        help="Output format (default: md)",
    )

    args = parser.parse_args()

    try:
        generator = ReleaseNotesGenerator(args.from_ref, args.to_ref, args.version)
        output = generator.generate()

        # Convert markdown to requested format with 80 char line wrapping
        extra_args = ["--wrap=auto", "--columns=80"]
        output = pypandoc.convert_text(
            output, args.format, format="md", extra_args=extra_args
        )

        print(output)
    except subprocess.CalledProcessError as e:
        print(f"Error: git command failed: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
