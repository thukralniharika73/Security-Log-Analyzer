import tempfile
import unittest
from pathlib import Path

from analyzer import analyze_file, parse_log_line


class AnalyzerTests(unittest.TestCase):
    def test_parse_valid_line(self):
        record = parse_log_line(
            "2026-10-22 09:10:00 username=alex ip=192.168.1.10 status=SUCCESS"
        )
        self.assertEqual(record["username"], "alex")
        self.assertEqual(record["status"], "SUCCESS")

    def test_invalid_line(self):
        self.assertIsNone(parse_log_line("not a valid record"))

    def test_counts_and_threshold(self):
        content = (
            "2026-10-22 09:10:00 username=a ip=203.0.113.25 status=FAIL\n"
            "2026-10-22 09:11:00 username=a ip=203.0.113.25 status=FAIL\n"
            "2026-10-22 09:12:00 username=a ip=203.0.113.25 status=FAIL\n"
            "bad line\n"
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            log_path = Path(temp_dir) / "test.log"
            log_path.write_text(content, encoding="utf-8")
            result = analyze_file(log_path, threshold=3)
        self.assertEqual(result["failed_logins"], 3)
        self.assertEqual(result["malformed_lines"], 1)
        self.assertEqual(result["suspicious_ips"], {"203.0.113.25": 3})


if __name__ == "__main__":
    unittest.main()
