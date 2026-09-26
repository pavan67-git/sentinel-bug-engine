import os
import tempfile
from pathlib import Path

from src.scanner import Scanner
from src.models.finding import Category

def test_scanner_finds_pattern():
    with tempfile.TemporaryDirectory() as tmp_dir:
        file_path = Path(tmp_dir) / 'sample.py'
        file_path.write_text('# TODO: fix this issue\nprint(\'hello\')\n')
        patterns = {
            'todo_finder': {
                'regex': 'TODO',
                'description': 'Detect TODO comments',
                'severity': 'LOW',
                'category': 'CODE_QUALITY'
            }
        }
        scanner = Scanner(target_path=tmp_dir, patterns=patterns)
        results = scanner.scan_path()
        assert any(finding.file_path == str(file_path) for finding in results), 'Pattern not detected'
        finding = next(f for f in results if f.file_path == str(file_path))
        assert finding.pattern_name == 'todo_finder'
        assert finding.severity == 'LOW'
        assert finding.category == Category.CODE_QUALITY
