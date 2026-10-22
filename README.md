# Security Log Analyzer

A small Python command-line project that parses a defined sample authentication-log format, summarizes successful and failed logins, flags IP addresses with repeated failed attempts, and writes a CSV report.

## Features

- Parses timestamps, usernames, IP addresses, and login status using a regular expression.
- Counts successful and failed authentication events.
- Flags IP addresses that meet a configurable failed-login threshold.
- Counts malformed non-empty lines instead of silently treating them as valid records.
- Exports per-IP failure counts to a CSV file.

## Requirements

- Python 3.9 or newer
- No third-party packages required

## Run

From the project folder:

```bash
python3 analyzer.py sample_data/auth.log
```

Change the flagging threshold and report location:

```bash
python3 analyzer.py sample_data/auth.log --threshold 2 --csv reports/custom-summary.csv
```

## Expected behavior

The included sample file contains seven valid log entries and one malformed line. With the default threshold of three, `203.0.113.25` should be flagged because it has three failed attempts. The script writes `reports/summary.csv`.

## Limitations

This is a learning/demo tool for the specific log format shown above. It does not connect to live systems, block IP addresses, prove malicious intent, or replace a production SIEM. A repeated failure is only a signal for further review.

## Project ownership and scope

If you use or adapt this implementation for an application, review and understand the code, run it yourself, and describe your contribution accurately. Do not present sample data as real production data.
