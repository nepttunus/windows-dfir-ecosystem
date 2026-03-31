from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from reporter.parsers import build_executive_summary, build_findings, collect_case_data


SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def ensure_dirs(case_path: Path) -> dict[str, Path]:
    reports = case_path / "11_reports"
    screenshots = case_path / "10_screenshots"
    share = case_path / "99_share_with_chatgpt"
    reports.mkdir(parents=True, exist_ok=True)
    screenshots.mkdir(parents=True, exist_ok=True)
    share.mkdir(parents=True, exist_ok=True)
    return {"reports": reports, "screenshots": screenshots, "share": share}


def render_html(case_path: Path, context: dict[str, Any], output_html: Path) -> None:
    template_dir = Path(__file__).parent / "templates"
    env = Environment(
        loader=FileSystemLoader(template_dir),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("report.html.j2")
    output_html.write_text(template.render(**context), encoding="utf-8")


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def render_screenshots_and_pdf(html_path: Path, screenshots_dir: Path, pdf_path: Path | None) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # pragma: no cover - dependency/runtime gate
        print(f"[!] Playwright unavailable, skipping screenshots/PDF: {exc}")
        return

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1600, "height": 1200})
        page.goto(html_path.resolve().as_uri(), wait_until="networkidle")
        page.screenshot(path=str(screenshots_dir / "full_report.png"), full_page=True)

        selectors = {
            "executive_summary.png": "#executive-summary",
            "findings.png": "#findings",
            "persistence.png": "#persistence",
            "network.png": "#network",
            "defender.png": "#defender",
        }
        for filename, selector in selectors.items():
            try:
                page.locator(selector).screenshot(path=str(screenshots_dir / filename))
            except Exception as exc:
                print(f"[!] Could not capture selector {selector}: {exc}")

        if pdf_path is not None:
            try:
                page.pdf(path=str(pdf_path), format="A4", print_background=True)
            except Exception as exc:
                print(f"[!] Could not render PDF: {exc}")

        browser.close()


def build_context(case_path: Path) -> dict[str, Any]:
    data = collect_case_data(case_path)
    findings = build_findings(data)
    findings_sorted = sorted(findings, key=lambda item: SEVERITY_ORDER.get(item.severity, 0), reverse=True)
    executive_summary = build_executive_summary(data, findings_sorted)

    summary = data.get("summary") or {}
    context = {
        "case_id": summary.get("CaseId", "UNKNOWN-CASE"),
        "hostname": summary.get("Hostname", "UNKNOWN-HOST"),
        "profile": summary.get("Profile", "UNKNOWN"),
        "collected_at_utc": summary.get("CollectedAtUtc", ""),
        "summary": summary,
        "computer_info": data.get("computer_info") or {},
        "findings": [f.to_dict() for f in findings_sorted],
        "executive_summary_markdown": executive_summary,
        "tasks": data.get("tasks") or [],
        "services": data.get("services") or [],
        "tcp_listeners": data.get("tcp_listeners") or [],
        "run_keys": data.get("run_keys") or [],
        "defender_status": data.get("defender_status") or {},
        "defender_threats": data.get("defender_threats") or [],
    }
    return context


def main() -> None:
    parser = argparse.ArgumentParser(description="Build HTML/PDF/screenshots from a collected DFIR case")
    parser.add_argument("--case-path", required=True, help="Path to the collected case directory")
    parser.add_argument("--render-pdf", action="store_true", help="Render a PDF version using Playwright")
    parser.add_argument("--take-screenshots", action="store_true", help="Capture screenshots using Playwright")
    args = parser.parse_args()

    case_path = Path(args.case_path).resolve()
    if not case_path.exists():
        raise SystemExit(f"Case path does not exist: {case_path}")

    dirs = ensure_dirs(case_path)
    context = build_context(case_path)

    html_path = dirs["reports"] / "report.html"
    pdf_path = dirs["reports"] / "report.pdf" if args.render_pdf else None
    findings_path = case_path / "09_findings" / "findings.json"
    findings_path.parent.mkdir(parents=True, exist_ok=True)
    summary_md_path = dirs["reports"] / "executive_summary.md"

    render_html(case_path, context, html_path)
    write_json(findings_path, context["findings"])
    summary_md_path.write_text(context["executive_summary_markdown"], encoding="utf-8")

    share_summary = {
        "case_id": context["case_id"],
        "hostname": context["hostname"],
        "profile": context["profile"],
        "collected_at_utc": context["collected_at_utc"],
        "findings_count": len(context["findings"]),
        "top_findings": context["findings"][:10],
    }
    write_json(dirs["share"] / "summary.json", share_summary)
    write_json(dirs["share"] / "findings.json", context["findings"])

    if args.take_screenshots or args.render_pdf:
        render_screenshots_and_pdf(
            html_path=html_path,
            screenshots_dir=dirs["screenshots"],
            pdf_path=pdf_path,
        )

    print(f"[+] HTML report: {html_path}")
    print(f"[+] Findings JSON: {findings_path}")
    print(f"[+] Executive summary: {summary_md_path}")
    if pdf_path:
        print(f"[+] PDF report: {pdf_path}")


if __name__ == "__main__":
    main()
