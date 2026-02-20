#Local File Browser Module - Browse local *.txt files without upload (FAST)
import os
import json
import time
import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import config
from core.debug_logger import logger


class LocalFileBrowser:
    #Secure local file browser - ROOT DIR (no full drive scans)

    def __init__(
        self,
        allowed_extensions: Tuple[str, ...] = (".txt", ".lst", ".urls"),
        *,
        preview_bytes: int = 8192,
        preview_lines: int = 5,
        preview_chars: int = 200,
        enable_line_count: bool = True,
        line_count_max_bytes: int = 2_000_000,
        cache_ttl_sec: float = 0.35,
    ):
        self.allowed_extensions = tuple(ext.lower() for ext in allowed_extensions)
        self.preview_bytes = int(preview_bytes)
        self.preview_lines = int(preview_lines)
        self.preview_chars = int(preview_chars)
        self.enable_line_count = bool(enable_line_count)
        self.line_count_max_bytes = int(line_count_max_bytes)
        self.cache_ttl_sec = float(cache_ttl_sec)
        self._dir_cache: Dict[Tuple[str, Optional[str]], Tuple[float, Dict]] = {}

        # === ROOT PRJ ===
        self.project_root = self._find_project_root()
        self._allowed_roots = [self.project_root]
        self.base_paths = self._get_project_subdirs()

        # Recent index in project data dir
        self._recent_index_path = self.project_root / ".data" / ".recent_targets.json"
        self._recent_index_path.parent.mkdir(parents=True, exist_ok=True)
        self._recent_index = self._load_recent_index()

        logger.info("FILE_BROWSER", "Initialized (PROJECT ROOT ONLY)", {
            "project_root": str(self.project_root),
            "extensions": self.allowed_extensions,
        })

    def _find_project_root(self) -> Path:
        #Find the main project root directory  by auto detect
        markers = [".git", "main.py", "app.py", "requirements.txt", "pyproject.toml", "setup.py", "config.py", "run.py"]
        current = Path.cwd().resolve()
        
        for path in [current] + list(current.parents):
            for marker in markers:
                if (path / marker).exists():
                    return path
        
        for attr in ["BASE_DIR", "PROJECT_ROOT", "ROOT_DIR"]:
            val = getattr(config, attr, None)
            if val:
                return Path(val).resolve()
        
        return current

    def _get_project_subdirs(self) -> List[Path]:
        #Get immediate subdirectories of root prj only. 
        subdirs = [self.project_root]
        
        for item in self.project_root.iterdir():
            if item.is_dir() and not item.name.startswith("."):
                subdirs.append(item)
        
        for common in ["targets", "data", "input", "files", "urls", "lists"]:
            common_path = self.project_root / common
            if common_path.exists() and common_path not in subdirs:
                subdirs.insert(1, common_path)
        
        return subdirs[:10]

    # --- Compatibility aliases ---
    def load_target_file(self, filepath: str) -> Dict:
        return self.read_target_file(filepath)

    def browse(self, path: str = ".") -> Dict:
        return self.browse_directory(path)

    # --- Async wrappers ---
    async def browse_directory_async(self, path: str = ".") -> Dict:
        return await asyncio.to_thread(self.browse_directory, path)

    async def read_target_file_async(self, filepath: str) -> Dict:
        return await asyncio.to_thread(self.read_target_file, filepath)

    # --- Main API ---
    def browse_directory(self, path: str = ".") -> Dict:
        """ Browse directory contents - root prj only """
        try:
            target_path = Path(path).expanduser().resolve(strict=False)

            if not self._is_within_project(target_path):
                logger.warning("FILE_BROWSER", "Path outside project blocked", {"path": path})
                return {"error": "Access denied - outside project root", "contents": []}

            if not target_path.exists():
                return {"error": "Path not found", "contents": []}

            if target_path.is_file():
                parent = target_path.parent
                return self._list_directory(parent, highlight=target_path.name)

            cache_key = (str(target_path), None)
            now = time.time()
            cached = self._dir_cache.get(cache_key)
            if cached and (now - cached[0]) <= self.cache_ttl_sec:
                return cached[1]

            result = self._list_directory(target_path)
            self._dir_cache[cache_key] = (now, result)
            return result

        except Exception as e:
            logger.error("FILE_BROWSER", f"Browse error: {e}")
            return {"error": str(e), "contents": []}

    def _list_directory(self, path: Path, highlight: Optional[str] = None) -> Dict:
        """List directory contents"""
        contents: List[Dict] = []

        try:
            if path.parent != path and self._is_within_project(path.parent):
                contents.append({
                    "name": "..",
                    "type": "directory",
                    "path": str(path.parent),
                    "size": None,
                    "modified": None,
                })

            try:
                with os.scandir(path) as it:
                    entries = list(it)
            except PermissionError:
                return {"error": "Permission denied", "contents": []}

            entries.sort(key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))

            total_files = 0
            total_dirs = 0

            for entry in entries:
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                    is_file = entry.is_file(follow_symlinks=False)

                    item = {
                        "name": entry.name,
                        "type": "directory" if is_dir else "file",
                        "path": entry.path,
                        "size": None,
                        "modified": None,
                    }

                    try:
                        st = entry.stat(follow_symlinks=False)
                        item["modified"] = st.st_mtime
                        if is_file:
                            item["size"] = st.st_size
                    except Exception:
                        pass

                    if is_dir:
                        total_dirs += 1
                    else:
                        total_files += 1

                    if is_file and Path(entry.name).suffix.lower() in self.allowed_extensions:
                        item["is_target"] = True
                        item["preview"] = self._fast_preview(entry.path)
                        
                        if self.enable_line_count and item.get("size") is not None:
                            if item["size"] <= self.line_count_max_bytes:
                                item["line_count"] = self._fast_line_count(entry.path)
                            else:
                                item["line_count"] = None

                    if highlight and entry.name == highlight:
                        item["highlighted"] = True

                    contents.append(item)

                except PermissionError:
                    continue
                except Exception as e:
                    logger.debug("FILE_BROWSER", f"Error reading {entry.path}: {e}")

            return {
                "current_path": str(path),
                "project_root": str(self.project_root),
                "contents": contents,
                "total_files": total_files,
                "total_dirs": total_dirs,
                "scope": "project_only"
            }

        except PermissionError:
            return {"error": "Permission denied", "contents": []}
        except Exception as e:
            return {"error": str(e), "contents": []}

    def read_target_file(self, filepath: str) -> Dict:
        """Read and parse target file."""
        try:
            target_path = Path(filepath).expanduser().resolve(strict=False)

            if not self._is_within_project(target_path):
                return {"error": "Access denied - outside project root", "urls": []}

            if not target_path.exists():
                return {"error": "File not found", "urls": []}

            if target_path.suffix.lower() not in self.allowed_extensions:
                return {"error": f"Invalid file type. Allowed: {self.allowed_extensions}", "urls": []}

            urls = []
            with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith("#"):
                        urls.append({"url": line, "line": line_num, "source": str(target_path)})

            self._update_recent_index(str(target_path))
            logger.info("FILE_BROWSER", f"Loaded {len(urls)} URLs from {target_path.name}")

            return {
                "filename": target_path.name,
                "path": str(target_path),
                "urls": urls,
                "count": len(urls),
            }

        except Exception as e:
            logger.error("FILE_BROWSER", f"Read error: {e}")
            return {"error": str(e), "urls": []}

    # --- Security ---
    def _is_within_project(self, path: Path) -> bool:
        """Strict check: path must be within root prj."""
        try:
            resolved = path.resolve(strict=False)
            resolved.relative_to(self.project_root)
            return True
        except ValueError:
            return False
        except Exception:
            return False

    def _is_allowed_path(self, path: Path) -> bool:
        """Legacy compatibility."""
        return self._is_within_project(path)

    # --- Quick access ---
    def get_quick_access(self) -> Dict:
        #Return project-only locations and recent files."""
        locations = []
        
        for path in self.base_paths:
            if path.exists() and self._is_within_project(path):
                locations.append({
                    "name": path.name or "project_root",
                    "path": str(path),
                    "type": "directory"
                })

        return {
            "project_root": str(self.project_root),
            "locations": locations,
            "recent_files": self._get_recent_files()
        }

    def scan_for_targets(self) -> List[Dict]:
        #FAST: Scan root prj + 1-level subdirs for target files.
        targets = []
        
        try:
            # Scan root only
            for item in self.project_root.iterdir():
                if item.is_file() and item.suffix.lower() in self.allowed_extensions:
                    try:
                        st = item.stat()
                        targets.append({
                            "name": item.name,
                            "path": str(item),
                            "size": st.st_size,
                            "modified": st.st_mtime,
                        })
                    except Exception:
                        continue
            
            # Scan common subdirs (1 level only)
            for subdir_name in ["targets", "data", "input", "files", "urls", "lists"]:
                subdir = self.project_root / subdir_name
                if subdir.exists() and subdir.is_dir():
                    try:
                        for item in subdir.iterdir():
                            if item.is_file() and item.suffix.lower() in self.allowed_extensions:
                                try:
                                    st = item.stat()
                                    targets.append({
                                        "name": f"{subdir_name}/{item.name}",
                                        "path": str(item),
                                        "size": st.st_size,
                                        "modified": st.st_mtime,
                                    })
                                except Exception:
                                    continue
                    except PermissionError:
                        continue
            
            targets.sort(key=lambda x: x["modified"], reverse=True)
            return targets
            
        except Exception as e:
            logger.error("FILE_BROWSER", f"Scan error: {e}")
            return []

    def _get_recent_files(self) -> List[Dict]:
        #Return recent files from project only
        out: List[Dict] = []
        try:
            items = self._recent_index.get("files", [])
            for p in items:
                try:
                    fp = Path(p)
                    if not self._is_within_project(fp) or not fp.exists():
                        continue
                    st = fp.stat()
                    out.append({
                        "name": fp.name,
                        "path": str(fp),
                        "modified": st.st_mtime,
                        "size": st.st_size,
                    })
                except Exception:
                    continue

            out.sort(key=lambda x: x["modified"], reverse=True)
            return out[:10]
        except Exception as e:
            logger.debug("FILE_BROWSER", f"Recent files error: {e}")
            return []

    def _load_recent_index(self) -> Dict:
        try:
            if self._recent_index_path.exists():
                return json.loads(self._recent_index_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            pass
        return {"files": []}

    def _save_recent_index(self) -> None:
        try:
            self._recent_index_path.parent.mkdir(parents=True, exist_ok=True)
            self._recent_index_path.write_text(json.dumps(self._recent_index, indent=2), encoding="utf-8")
        except Exception as e:
            logger.debug("FILE_BROWSER", f"Save recent index error: {e}")

    def _update_recent_index(self, filepath: str) -> None:
        try:
            files = self._recent_index.get("files", [])
            files = [f for f in files if f != filepath]
            files.insert(0, filepath)
            self._recent_index["files"] = files[:20]
            self._save_recent_index()
        except Exception:
            pass

    # --- Fast helpers ---
    def _fast_preview(self, filepath: str) -> str:
        try:
            with open(filepath, "rb") as f:
                chunk = f.read(self.preview_bytes)
            text = chunk.decode("utf-8", errors="ignore")
            lines = text.splitlines()[: self.preview_lines]
            preview = "\n".join(lines).strip()
            if len(preview) > self.preview_chars:
                preview = preview[: self.preview_chars].rstrip() + "…"
            return preview if preview else ""
        except Exception:
            return "Unable to preview"

    def _fast_line_count(self, filepath: str) -> int:
        count = 0
        try:
            with open(filepath, "rb") as f:
                while True:
                    buf = f.read(1024 * 1024)
                    if not buf:
                        break
                    count += buf.count(b"\n")
            return count + 1 if count > 0 else 0
        except Exception:
            return 0

file_browser = LocalFileBrowser()