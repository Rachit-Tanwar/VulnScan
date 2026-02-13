import os, sys, traceback
import csv, json
import datetime, platform
import webbrowser, socket

from pathlib import Path

import checks_windows, checks_linux


def detect_platorm():
    plat = platform.system().lower()
    if "windows" in plat:
        return "windows"
    if "linux" in plat:
        return "linux"
    return plat


def compute_score(findings):
    """
    Deduct points based on findings' severity. Stacking softened after 60 points
    to not get instant 0 scores.
    """
    base_weights = {"Critical" : 35, "High" : 20, "Medium" : 8, "Low" : 2}
    penalty = sum(base_weights.get(f.get("severity", "Low"), 2) for f in findings)
    
    if penalty > 60:
        penalty = 60 + (0.5 * (penalty - 60))

    penalty = min(100, penalty)

    return max(0, int(100 - penalty))


def top_recommendations(findings, limit=5):
    seen = set()
    rec = []

    for f in sorted(findings, key=lambda x: x.get("cvss", 0.0), reverse=True):
        r = f.get("remediation", "").strip()
        if r and r not in seen:
            seen.add(r); rec.append(r)
        if len(rec) >= limit:
            break
    return rec or ["No critical issues detected.\nMaintain regular updates & backups.\nDoing good\n."]


def render_report(context):
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    tpl_dir = Path(__file__).parent / "templates"
    env = Environment(loader=FileSystemLoader(str(tpl_dir)), autoescape=select_autoescape(['html', 'xml']))
    tpl = env.get_template('report.html.j2')
    html = tpl.render(**context)
    with open("report.html", 'w', encoding="utf-8") as fd:
        fd.write(html)


def write_csv(host, findings):
    with open("findings.csv", 'w', newline='', encoding="utf-8") as fd:
        writer = csv.writer(fd)
        writer.writerow(["host", "os", "timestamp", "id", "title", "severity", "cvss", "remediation", "evidence"])
        t_stmp = datetime.datetime.now().isoformat(timespec="seconds")
        for fi in findings:
            writer.writerow(
                [
                    host["hostname"], host["os"], t_stmp, fi.get("id", ""), 
                    fi.get("title", ""), fi.get("severity", ""), fi.get("cvss", ""), 
                    fi.get("remediation", ""), fi.get("evidence", "")
                ]
            )


def group_by_severity(findings):
    g:dict = {"Critical" : [], "High" : [], "Medium" : [], "Low" : []}
    for f in findings:
        g.setdefault(f["severity"], []).append(f)
    return g


def main():
    hostname = socket.gethostname()
    platform = detect_platorm()
    host = {"hostname" : hostname, "os" : platform, "detail" : ""}

    try:
        if platform == "windows":
            raw = checks_windows.gather()
            host["detail"] = (raw.get("os_detail") or "")[:160]
            findings = checks_windows.analyze(raw)
        elif platform == "linux":
            raw = checks_linux.gather()
            host["detail"] = (raw.get("os_detail"), "")
            findings = checks_linux.analyze(raw)
        else:
            raw = {"platform" : sys.platform}
            findings = [{
                "id" : "UNSUPPORTED", "title" : f"Unsupported platform : {platform}",
                "cvss" : 0.0, "severity" : "Low",
                "remediation" : "Run on Windows or Linux system.",
                "evidence" : sys.platform
            }]
    except Exception:
        raw = {"error" : "runtime exception"}
        findings = [{
            "id" : "RUNTIME-ERROR", "title" : "Runtime error while gathering checks.",
            "cvss" : 0.0, "severity" : "Low",
            "remediation" : "Inspect debug.json; Run with Admin/sudo if needed",
            "evidence" : traceback.format_exc()
        }]

    with open("debug.json", 'w', encoding="utf-8") as fdj:
        json.dump(raw, fdj, indent=2)

    counts = {"Critical" : 0, "High" : 0, "Medium" : 0, "Low" : 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"],0) + 1

    score = compute_score(findings)

    context = {
        "host" : host, "findings" : findings, "by_sev" : group_by_severity(findings), "counts" : counts,
        "summary" : { "score" : score,"summary_text" : "Address Critical/High severity items first.\nLower score means higher risk."},
        "top_recommendations" : top_recommendations(findings), "meta" : {"generated" : datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}
    }

    write_csv(host, findings)
    render_report(context)

    try:
        webbrowser.open_new_tab("report.html")
    except Exception:
        pass

    print(f"[OK] Generated report.html and findings.csv (Overall Score = {score/100})")

if __name__ == "__main__":
    main()
