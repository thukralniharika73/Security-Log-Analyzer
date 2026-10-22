"""Analyze sample authentication logs and summarize repeated failed logins.

Expected log format:
2026-10-22 09:10:00 username=alex ip=192.168.1.10 status=FAIL
"""
import argparse
import csv
import re
from collections import Counter
from pathlib import Path

LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"username=(?P<username>\S+)\s+"
    r"ip=(?P<ip>\S+)\s+"
    r"status=(?P<status>SUCCESS|FAIL)$",
    re.IGNORECASE,
)


def parse_log_line(line):
    """Return parsed fields, or None if the line does not match the expected format."""
    match = LOG_PATTERN.match(line.strip())
    if not match:
        return None
    record = match.groupdict()
    record["status"] = record["status"].upper()
    return record


def analyze_file(input_path, threshold=3):
    records = []
    malformed_lines = 0

    with open(input_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            if not line.strip():
                continue
            record = parse_log_line(line)
            if record is None:
                malformed_lines += 1
            else:
                records.append(record)

    failed_by_ip = Counter(
        record["ip"] for record in records if record["status"] == "FAIL"
    )
    suspicious_ips = {
        ip: count for ip, count in failed_by_ip.items() if count >= threshold
    }

    return {
        "records": records,
        "total_entries": len(records),
        "successful_logins": sum(r["status"] == "SUCCESS" for r in records),
        "failed_logins": sum(r["status"] == "FAIL" for r in records),
        "malformed_lines": malformed_lines,
        "failed_by_ip": failed_by_ip,
        "suspicious_ips": suspicious_ips,
    }


def write_csv_report(result, output_path):
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as report_file:
        writer = csv.writer(report_file)
        writer.writerow(["ip_address", "failed_attempts", "flagged"])
        for ip, count in sorted(result["failed_by_ip"].items()):
            writer.writerow([ip, count, "YES" if ip in result["suspicious_ips"] else "NO"])


def main():
    parser = argparse.ArgumentParser(description="Summarize authentication log activity.")
    parser.add_argument("logfile", help="Path to a text file containing authentication logs")
    parser.add_argument("--threshold", type=int, default=3,
                        help="Failed attempts from one IP needed to flag it (default: 3)")
    parser.add_argument("--csv", default="reports/summary.csv",
                        help="Output CSV report path (default: reports/summary.csv)")
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if not Path(args.logfile).is_file():
        parser.error(f"Log file not found: {args.logfile}")

    result = analyze_file(args.logfile, args.threshold)
    write_csv_report(result, args.csv)

    print("Authentication Log Summary")
    print("--------------------------")
    print(f"Valid entries:       {result['total_entries']}")
    print(f"Successful logins:   {result['successful_logins']}")
    print(f"Failed logins:       {result['failed_logins']}")
    print(f"Malformed lines:     {result['malformed_lines']}")
    print(f"Flagged IPs (>= {args.threshold} failures):")
    if result["suspicious_ips"]:
        for ip, count in sorted(result["suspicious_ips"].items()):
            print(f"  {ip}: {count} failed attempts")
    else:
        print("  None")
    print(f"CSV report written to: {args.csv}")


if __name__ == "__main__":
    main()
