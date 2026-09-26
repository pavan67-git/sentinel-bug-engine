"""Universal multi-language parser and semantic code chunker."""
import os
import re
from typing import List, Dict, Optional, Tuple
from pydantic import BaseModel, Field

EXTENSION_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".cs": "csharp",
    ".rs": "rust",
    ".php": "php",
    ".rb": "ruby",
    ".kt": "kotlin",
    ".swift": "swift",
    ".scala": "scala",
    ".sh": "bash",
    ".sql": "sql",
}

class CodeChunk(BaseModel):
    file_path: str
    language: str
    chunk_type: str = "function_or_block"
    name: str = "anonymous"
    start_line: int
    end_line: int
    content: str
    context_imports: List[str] = Field(default_factory=list)


class UniversalParser:
    """Universal language detector and semantic block extractor."""

    @staticmethod
    def detect_language(file_path: str) -> Optional[str]:
        ext = os.path.splitext(file_path)[1].lower()
        return EXTENSION_TO_LANGUAGE.get(ext)

    @staticmethod
    def parse_file(file_path: str) -> List[CodeChunk]:
        language = UniversalParser.detect_language(file_path)
        if not language:
            return []

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            return []

        if not lines:
            return []

        imports = UniversalParser._extract_imports(lines, language)

        if language == "python":
            return UniversalParser._chunk_python(file_path, lines, imports)
        else:
            return UniversalParser._chunk_c_style(file_path, lines, language, imports)

    @staticmethod
    def _extract_imports(lines: List[str], language: str) -> List[str]:
        imports = []
        for line in lines[:50]: # Look at top of file
            stripped = line.strip()
            if language == "python" and (stripped.startswith("import ") or stripped.startswith("from ")):
                imports.append(stripped)
            elif language in ["javascript", "typescript"] and (stripped.startswith("import ") or "require(" in stripped):
                imports.append(stripped)
            elif language == "java" and stripped.startswith("import "):
                imports.append(stripped)
            elif language == "go" and (stripped.startswith("import") or stripped.startswith('"')):
                imports.append(stripped)
        return imports

    @staticmethod
    def _chunk_python(file_path: str, lines: List[str], imports: List[str]) -> List[CodeChunk]:
        import ast
        source = "".join(lines)
        chunks: List[CodeChunk] = []

        try:
            tree = ast.parse(source, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    start = node.lineno
                    end = getattr(node, "end_lineno", start + 10)
                    chunk_content = "".join(lines[start - 1 : end])
                    chunks.append(
                        CodeChunk(
                            file_path=file_path,
                            language="python",
                            chunk_type="class" if isinstance(node, ast.ClassDef) else "function",
                            name=node.name,
                            start_line=start,
                            end_line=end,
                            content=chunk_content,
                            context_imports=imports,
                        )
                    )
        except Exception:
            pass

        # Fallback to sliding window if AST couldn't parse or found no functions
        if not chunks:
            chunks = UniversalParser._chunk_sliding_window(file_path, lines, "python", imports)

        return chunks

    @staticmethod
    def _chunk_c_style(file_path: str, lines: List[str], language: str, imports: List[str]) -> List[CodeChunk]:
        """Generic bracket-depth chunker for JS, TS, Java, Go, C++, C#, etc."""
        chunks: List[CodeChunk] = []
        total_lines = len(lines)
        i = 0

        # Pattern to detect function/method signatures
        func_sig = re.compile(r"""^\s*(?:(?:export|public|private|protected|static|async|function|func|def)\s+)+([a-zA-Z0-9_$]+)\s*\(""")

        while i < total_lines:
            line = lines[i]
            match = func_sig.search(line)
            if match and "{" in "".join(lines[i : min(i + 3, total_lines)]):
                func_name = match.group(1)
                start_line = i + 1
                brace_count = 0
                started = False
                j = i

                while j < total_lines:
                    for char in lines[j]:
                        if char == "{":
                            brace_count += 1
                            started = True
                        elif char == "}":
                            brace_count -= 1
                    if started and brace_count <= 0:
                        break
                    j += 1

                end_line = min(j + 1, total_lines)
                content = "".join(lines[start_line - 1 : end_line])
                chunks.append(
                    CodeChunk(
                        file_path=file_path,
                        language=language,
                        chunk_type="function",
                        name=func_name,
                        start_line=start_line,
                        end_line=end_line,
                        content=content,
                        context_imports=imports,
                    )
                )
                i = max(j, i + 1)
            else:
                i += 1

        if not chunks:
            chunks = UniversalParser._chunk_sliding_window(file_path, lines, language, imports)

        return chunks

    @staticmethod
    def _chunk_sliding_window(file_path: str, lines: List[str], language: str, imports: List[str], window_size: int = 60, overlap: int = 15) -> List[CodeChunk]:
        chunks: List[CodeChunk] = []
        total = len(lines)
        if total == 0:
            return []

        start = 0
        idx = 1
        while start < total:
            end = min(start + window_size, total)
            content = "".join(lines[start:end])
            chunks.append(
                CodeChunk(
                    file_path=file_path,
                    language=language,
                    chunk_type="window_block",
                    name=f"block_{idx}",
                    start_line=start + 1,
                    end_line=end,
                    content=content,
                    context_imports=imports,
                )
            )
            idx += 1
            if end >= total:
                break
            start += (window_size - overlap)

        return chunks
