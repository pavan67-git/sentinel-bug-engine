"""LLM Provider supporting Google Gemini, OpenAI, Ollama, and offline hybrid mode."""
import os
import json
import requests
from typing import List, Dict, Any, Optional
from src.models.finding import Finding, Severity, Category, FixPatch
from src.rules.catalog import get_cwe
from src.parsers.universal import CodeChunk
from src.llm.prompts import SYSTEM_PROMPT_SECURITY, USER_PROMPT_ANALYZE

class LLMProvider:
    """LLMProvider encapsulates interaction with an LLM service.

    It supports Google Gemini, OpenAI‑compatible APIs, and can be extended for
    other providers. API keys are sourced in the following order:

    1. Explicit ``api_key`` argument.
    2. Environment variables ``GEMINI_API_KEY`` or ``OPENAI_API_KEY``.
    3. A ``config.json`` file at the project root containing a mapping like
       ``{"gemini_api_key": "...", "openai_api_key": "..."}``.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gemini-2.5-flash"):
        self.model = model
        # Determine provider type early for later checks
        self.is_gemini = "gemini" in model.lower()
        # Resolve API key from argument, environment, or config file
        self.api_key = api_key or self._load_api_key_from_env() or self._load_api_key_from_config()

    @staticmethod
    def _load_api_key_from_env() -> Optional[str]:
        """Return an API key from known environment variables or a .env file.

        The method first checks the ``GEMINI_API_KEY`` and ``OPENAI_API_KEY``
        environment variables. If neither is set, it attempts to load a ``.env``
        file located at the project root (two directories up from this file).
        ``python‑dotenv`` is optional – if the package is missing the function
        simply falls back to the environment variables.
        """
        # Direct environment variables first
        key = os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if key:
            return key
        # Attempt to load from .env using python‑dotenv if available
        try:
            from pathlib import Path
            from dotenv import load_dotenv
            env_path = Path(__file__).parents[2] / ".env"
            if env_path.is_file():
                load_dotenv(dotenv_path=env_path)
                return os.environ.get("GEMINI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        except Exception:
            # dotenv not installed or loading failed – silently ignore
            pass
        return None

    @staticmethod
    def _load_api_key_from_config() -> Optional[str]:
        """Load API keys from a ``config.json`` file located at the project root.

        The file should contain keys ``gemini_api_key`` and/or ``openai_api_key``.
        If the file does not exist or does not contain a matching key, ``None``
        is returned.
        """
        from pathlib import Path
        import json

        config_path = Path(__file__).parents[2] / "config.json"
        if not config_path.is_file():
            return None
        try:
            data = json.loads(config_path.read_text())
        except Exception:
            return None
        # Choose appropriate key based on model/provider
        if "gemini" in data.get("model", "").lower() or "gemini" in (data.get("gemini_api_key", "").lower()):
            return data.get("gemini_api_key")
        return data.get("openai_api_key")

    def set_api_key(self, api_key: str) -> None:
        """Programmatically set or override the API key.

        This is useful for tests or when the key is obtained from a secret store
        at runtime.
        """
        self.api_key = api_key


    def analyze_chunk(self, chunk: CodeChunk, finding_id_prefix: str = "AI") -> List[Finding]:
        """Analyze a code chunk using the configured LLM."""
        if not self.api_key:
            return []

        prompt = USER_PROMPT_ANALYZE.format(
            language=chunk.language,
            file_path=chunk.file_path,
            start_line=chunk.start_line,
            end_line=chunk.end_line,
            imports="\n".join(chunk.context_imports) if chunk.context_imports else "None",
            code=chunk.content
        )

        try:
            if self.is_gemini:
                raw_response = self._call_gemini(prompt)
            else:
                raw_response = self._call_openai_compatible(prompt)

            return self._parse_llm_json(raw_response, chunk, finding_id_prefix)
        except Exception:
            return []

    def _call_gemini(self, prompt: str) -> str:
        """Call the Gemini REST endpoint.

        ``self.api_key`` must be set; otherwise a ``ValueError`` is raised.
        """
        if not self.api_key:
            raise ValueError("Gemini API key is not configured.")
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {"text": SYSTEM_PROMPT_SECURITY + "\n\n" + prompt}
                    ]
                }
            ],
            "generationConfig": {
                "responseMimeType": "application/json",
                "temperature": 0.1
            }
        }
        res = requests.post(url, json=payload, timeout=30)
        res.raise_for_status()
        data = res.json()
        return data["candidates"][0]["content"]["parts"][0]["text"]

    def _call_openai_compatible(self, prompt: str) -> str:
        """Call an OpenAI‑compatible endpoint.

        ``self.api_key`` must be set; otherwise a ``ValueError`` is raised.
        """
        if not self.api_key:
            raise ValueError("OpenAI API key is not configured.")
        url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1/chat/completions")
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT_SECURITY},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1
        }
        res = requests.post(url, headers=headers, json=payload, timeout=30)
        res.raise_for_status()
        return res.json()["choices"][0]["message"]["content"]

    def _parse_llm_json(self, raw_json: str, chunk: CodeChunk, prefix: str) -> List[Finding]:
        findings: List[Finding] = []
        try:
            data = json.loads(raw_json)
            raw_findings = data.get("findings", [])
            for idx, item in enumerate(raw_findings):
                cwe_id = item.get("cwe_id")
                cwe_info = get_cwe(cwe_id) if cwe_id else None

                fix_patch = None
                if item.get("suggested_fix_summary") or item.get("diff"):
                    fix_patch = FixPatch(
                        summary=item.get("suggested_fix_summary", "Suggested fix"),
                        diff=item.get("diff", "")
                    )

                finding = Finding(
                    id=f"{prefix}-{idx+1:03d}",
                    file_path=chunk.file_path,
                    start_line=item.get("start_line", chunk.start_line),
                    end_line=item.get("end_line", chunk.end_line),
                    title=item.get("title", "Detected Bug"),
                    description=item.get("description", ""),
                    severity=Severity(item.get("severity", "MEDIUM").upper()),
                    category=Category(item.get("category", "SECURITY").upper()),
                    cwe=cwe_info,
                    tainted_flow=item.get("tainted_flow", []),
                    code_snippet=chunk.content[:400],
                    suggested_fix=fix_patch,
                    tags=["ai-detected", chunk.language]
                )
                findings.append(finding)
        except Exception:
            pass
        return findings
