"""
File dump management — writes user lists with a prefix.
Only creates files that are non-empty.
"""

import os
from typing import Optional, Set


class DumpManager:
    def __init__(self, prefix: Optional[str] = None):
        self.prefix      = prefix
        self._all:  Set[str] = set()
        self._spn:  Set[str] = set()
        self._np:   Set[str] = set()

    def add_user(self, sam: str) -> None:
        if sam:
            self._all.add(sam.lower())

    def add_spn_user(self, sam: str) -> None:
        if sam:
            self._all.add(sam.lower())
            self._spn.add(sam.lower())

    def add_np_user(self, sam: str) -> None:
        if sam:
            self._all.add(sam.lower())
            self._np.add(sam.lower())

    def write_files(self) -> list[str]:
        """Write non-empty prefixed files. Returns list of written file paths."""
        written = []
        files = {
            f"{self.prefix}_all_users.txt": self._all,
            f"{self.prefix}_spn_users.txt": self._spn,
            f"{self.prefix}_np_users.txt":  self._np,
        }
        for path, users in files.items():
            if not users:
                continue
            self._write(path, users)
            written.append(path)
        return written

    def write_user_file(self, path: str) -> Optional[str]:
        """Write all users (one login per line) to an exact path, e.g. for
        `nxc ... -u <path>`. Returns the path, or None if there were no users."""
        if not self._all:
            return None
        self._write(path, self._all)
        return path

    @staticmethod
    def _write(path: str, users: Set[str]) -> None:
        with open(path, "w") as f:
            for u in sorted(users):
                f.write(u + "\n")
