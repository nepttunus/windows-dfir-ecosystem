from reporter.parsers import build_findings


def test_detects_encoded_powershell_task():
    data = {
        "tasks": [
            {
                "TaskName": "Updater",
                "TaskPath": "\\",
                "Actions": "powershell.exe -enc SQBFAFgA",
            }
        ],
        "services": [],
        "run_keys": [],
        "defender_threats": [],
        "tcp_listeners": [],
        "defender_status": {},
    }
    findings = build_findings(data)
    assert any(f.title == "Scheduled task with encoded PowerShell" for f in findings)


def test_detects_defender_findings():
    data = {
        "tasks": [],
        "services": [],
        "run_keys": [],
        "defender_threats": [{"ThreatName": "HackTool:Win32/Mimikatz"}],
        "tcp_listeners": [],
        "defender_status": {},
    }
    findings = build_findings(data)
    assert any(f.title == "Microsoft Defender detections present" for f in findings)
