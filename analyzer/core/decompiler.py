"""Decompilation manager integrating JADX CLI with Dalvik bytecode disassembly as the primary ground truth."""
import os
import shutil
import subprocess
import logging
from typing import Optional, Dict

logger = logging.getLogger(__name__)


class Decompiler:
    """Manages JADX decompilation when available or extracts source snippets to assist human and AI readability."""

    def __init__(self, jadx_path: Optional[str] = None):
        self.jadx_path = jadx_path or shutil.which("jadx")

    def is_available(self) -> bool:
        return self.jadx_path is not None and os.path.exists(self.jadx_path)

    def decompile(self, apk_path: str, output_dir: str) -> bool:
        """Runs JADX CLI to produce Java source files for readable snippet extraction."""
        if not self.is_available():
            logger.info("JADX binary not found in PATH; using Dalvik static bytecode disassembly as source of truth.")
            return False

        try:
            cmd = [
                self.jadx_path,
                "-d", output_dir,
                "--no-res",
                "--show-bad-code",
                apk_path
            ]
            logger.info(f"Running JADX: {' '.join(cmd)}")
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
            return res.returncode == 0
        except Exception as e:
            logger.warning(f"JADX decompilation failed or timed out: {e}")
            return False

    def extract_method_source(self, decompiled_dir: str, class_name: str, method_name: str) -> Optional[str]:
        """Extracts a method snippet from a decompiled Java file if it exists."""
        if not decompiled_dir or not os.path.exists(decompiled_dir):
            return None

        # Path: decompiled_dir/sources/com/example/MyClass.java or decompiled_dir/sources/defpackage/a.java
        rel_path = class_name.replace(".", "/") + ".java"
        possible_paths = [
            os.path.join(decompiled_dir, "sources", rel_path),
            os.path.join(decompiled_dir, rel_path),
            os.path.join(decompiled_dir, "sources", "defpackage", os.path.basename(rel_path)),
        ]

        for p in possible_paths:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    # Look for method definition
                    search_targets = [f" {method_name}(", f"\t{method_name}(", f"\n{method_name}("]
                    for target in search_targets:
                        pos = content.find(target)
                        if pos != -1:
                            start = max(0, content.rfind("\n", 0, pos))
                            lines = content[start:].split("\n")[:20]
                            return "\n".join(lines)
                except Exception:
                    pass
        return None
