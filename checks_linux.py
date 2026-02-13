import subprocess, re
import json as _json


def _sh(cmd: str) -> tuple[bool, str]:
    try:
        out = subprocess.check_output(["bash", "-lc", cmd], stderr=subprocess.STDOUT, text=True, timeout=30)
        return True, out.strip()
    except Exception as e:
        return False, f"ERR: {e}"


def _scan_localhost_top_ports(ports):
    import socket
    open_ports = []
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
            if s.connect_ex(("127.0.0.1", p)) == 0:
                open_ports.append(p)
        except Exception:
            pass
        finally:
            try:
                s.close
            except:
                pass
    return open_ports

def gather() -> dict:
    os_name = "Linux"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    os_name = line.split('=', 1)[1].strip().strip('"')
                    break
    except:
        pass

    ok1, ufw = _sh("command -v ufw >/dev/null 2>&1 && ufw status | head -n1 || echo 'absent'")
    ok2, firewalld = _sh("systemctl is-active firewalld || echo inactive")

    try:
        with open("/etc/ssh/sshd_config") as f:
            ssh_cfg = f.read()
    except Exception as e:
        ssh_cfg = f"ERR: {e}"

    def get_val(key, default="unset"):
        m = re.search(rf"(?i)^s*{key}\s+(\S+)", ssh_cfg, re.MULTILINE)
        return m.group(1).lower() if m else default

    permitroot = get_val("PermitRootLogin")
    pwauth = get_val("PasswordAuthentication")
    empty_pw = get_val("PermitEmptyPasswords")
    protocol = get_val("Protocol")

    ok3, upd = _sh(
        "if command -v apt >/dev/null 2>&1; then apt lis --upgradable 2>/dev/null | wc -l; "
            "elif command -v dnf >/dev/null 2>&1; then dnf check-update 2>/dev/null | wc -l; "
            "elif command -v yum >/dev/null 2>&1; then yum check-update 2>/dev/null | wc -l; "
            "else echo unknown fi"
    )

    minlen = None
    try:
        with open("/etc/login.defs") as f:
            for line in f:
                if line.strip().startswith("PASS_MIN_LEN"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        minlen = int(parts[1])
                    break
    except:
        pass

    ok4, ports_csv = _sh("command -v ss >/dev/null 2>&1 && ss -lntuH | awk '{print $5}' | sed 's/.*://' | sort -n | uniq | paste -sd, - || echo ''")
    active_ports = _scan_localhost_top_ports([21, 22, 23, 80, 443, 445, 139, 3306, 5432, 6379, 27017, 5900])

    ok_lsblk, lsblk_json = _sh("lsblk -o NAME,RM,RO,TYPE,MOUNTPOINT,FSTYPE,TRAN -J 2>/dev/null || echo '{}'")

    ok_mnt, mounts = _sh(r"findmnt -rno TARGET,OPTIONS | sed 's \+/ /g' || true")

    ok_aut, aut_hits = _sh("for m in $(findmnt -rno TARGET); do "
        " if [ -f \"$m/autorun.inf\" ]; then echo \"$m/autorun.inf\"; fi; "
        "done")

    return {
        "platform":"linux",
        "os_detail":os_name,
        "ufw": ufw, "firewalld": firewalld,
        "ssh_permitrootlogin": permitroot,
        "ssh_passwordauth": pwauth,
        "ssh_permitemptypasswords": empty_pw,
        "ssh_protocol": protocol,
        "updates": upd,
        "min_password_length": minlen,
        "listening_ports": ports_csv,
        "active_ports": active_ports,
        "lsblk_raw": lsblk_json if ok_lsblk else lsblk_json,
        "mounts_raw": mounts if ok_mnt else mounts,
        "autorun_hits_raw": aut_hits if ok_aut else aut_hits,
    }


def analyze(data: dict) -> list[dict]:
    from cvss_map import map_config_to_cvss
    findings = []

    def add(id_, title, key, remediation, evidence):
        cvss, sev = map_config_to_cvss(key, None)
        findings.append({"id":id_, "title":title, "cvss":cvss, "severity":sev, "remediation":remediation, "evidence":evidence})

    if str(data.get("ssh_permitrootlogin", "")).lower() != "no":
        add("LINUX-SSH-ROOT","SSH PermitRootLogin is not 'no'",
            "linux_permitroot_not_no","Set PermitRootLogin no and restart sshd.", f"PermitRootLogin={data.get('ssh_permitrootlogin')}")

    if str(data.get("ssh_passwordauth","")).lower() != "no":
        add("LINUX-SSH-PWAUTH","SSH PasswordAuthentication is not 'no'",
            "linux_passwordauth_not_no","Disable PasswordAuthentication; use SSH keys.", f"PasswordAuthentication={data.get('ssh_passwordauth')}")
    if str(data.get("ssh_peritemptypasswords","")).lower() == "yes":
        add("LINUX-SSH-EMPTYPW","SSH PermitEmptyPasswords is 'yes'",
            "linux_peritemptypasswords_yes","Set PermitEmptyPasswords no.", f"PermitEmptyPasswords={data.get('ssh_peritemptypasswords')}")

    prot = str(data.get("ssh_protocol","")).strip()
    if prot and prot != "2" and prot != "unset":
        add("LINUX-SSH-PROTO1","SSH Protocol 1 appears enabled",
            "linux_ssh_protocol1","Force Protocol 2 (Protocol 2).", f"Protocol={prot}")

    ufw = data.get("ufw","").lower()
    firewalld = str(data.get("firewalld","")).strip().lower()
    if ("status: active" not in ufw) and (firewalld != "active"):
        add("LINUX-FW","Host firewall is not active (ufw/firewalld)",
            "linux_host_firewall_off","Enable ufw or firewalld; allow only required ports.", f"ufw='{data.get('ufw')}', firewalld='{data.get('firewalld')}'")

    upd = str(data.get("updates", "")).strip()
    if upd not in ("0", "1", "unknown", ""):
        add("LINUX-UPDATES","Pending OS/package updates detected",
            "linux_updates_pending","Update packages regularly (apt/dnf/yum).", f"updates_count_hint={upd}")

    minlen = data.get("min_password_length")
    if isinstance(minlen, int) and minlen < 12:
        add("LINUX-PASSLEN", f"Minimum password length is {minlen} (<12)",
            "linux_min_passlen_lt12","Increase PASS_MIN_LEN in /etc/login.defs to at least 12.", f"PASS_MIN_LEN={minlen}")

    ports_csv = str(data.get("listening_ports", "")).strip()
    listen = []
    if ports_csv:
        try:
            listen = sorted({int(x) for x in ports_csv.split(",") if x.strip().isdigit()})
        except Exception:
            listen = []
    for p in data.get("active_ports", []):
        if p not in listen: 
            listen.append(p)

    riskful = {
        22:   ("LINUX-NET-SSH",     "SSH (22) is listening","linux_listen_ssh",
               "If exposed, disable PasswordAuthentication; use keys; restrict via firewall."),
        21:   ("LINUX-NET-FTP",     "FTP (21) is listening","linux_listen_ftp",
               "Avoid plain FTP; use SFTP/FTPS; restrict via firewall."),
        23:   ("LINUX-NET-TELNET",  "Telnet (23) is listening","linux_listen_telnet",
               "Disable Telnet; use SSH."),
        445:  ("LINUX-NET-SMB",     "SMB (445) is listening","linux_listen_smb",
               "Restrict SMB; avoid SMBv1; firewall."),
        139:  ("LINUX-NET-NB",      "NetBIOS (139) is listening","linux_listen_smb",
               "Avoid legacy SMB/NetBIOS; firewall."),
        3306: ("LINUX-NET-MYSQL",   "MySQL (3306) is listening","linux_listen_mysql",
               "Bind to localhost/private; auth; firewall."),
        5432: ("LINUX-NET-POSTGRES","PostgreSQL (5432) is listening","linux_listen_postgres",
               "Bind to localhost/private; firewall; auth."),
        6379: ("LINUX-NET-REDIS",   "Redis (6379) is listening","linux_listen_redis",
               "Never expose publicly; require auth; firewall."),
        27017:("LINUX-NET-MONGO",   "MongoDB (27017) is listening","linux_listen_mongo",
               "Bind to localhost/private; firewall; auth."),
        5900: ("LINUX-NET-VNC",     "VNC (5900) is listening","linux_listen_vnc",
               "Restrict VNC via SSH tunnel/VPN; firewall."),
        80:   ("LINUX-NET-HTTP",    "HTTP (80) is listening","linux_listen_ftp",
               "Avoid public HTTP; prefer HTTPS; firewall appropriately."),
        443:  ("LINUX-NET-HTTPS",   "HTTPS (443) is listening","linux_listen_postgres",
               "Restrict exposure to required subnets; ensure strong TLS."),
    }
    for p, (fid, title, key, rem) in riskful.items():
        if p in listen:
            cvss, sev = map_config_to_cvss(key, None)
            findings.append({"id": fid, "title": title, "cvss": cvss, "severity": sev, "remediation": rem, "evidence": f"listening_port ={p}"})

    lsblk = {}
    try:
        lsblk = _json.loads(data.get("lsblk_raw", "{}") or "{}")
    except Exception:
        lsblk = {}

    mounts_raw = data.get("mounts_raw", "") or ""
    mnt_opts = {}
    for line in mounts_raw.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            tgt = parts[0].strip()
            opts = parts[1].strip()
            mnt_opts[tgt] = opts

    removable_mounts = []
    def walk_blk(blk):
        if isinstance(blk, list):
            for b in blk:
                walk_blk(b)
        elif isinstance(blk, dict):
            rm = str(blk.get("rm", "") or blk.get("RM", "")).strip()
            tran = str(blk.get("tran", "") or blk.get("TRAN", "")).lower()
            mnt = blk.get("mountpoint") or blk.get("MOUNTPOINT")
            fstype = (blk.get("fstype") or blk.get("FSTYPE") or "").lower()
            if rm in ("1", "true", "True") and (tran == "usb" or tran == "") and mnt:
                removable_mounts.append({"mount": mnt, "fstype": fstype})

            if "children" in blk and isinstance(blk["children"], list):
                walk_blk(blk["children"])
    walk_blk(lsblk.get("blockdevices", []))

    for rmv in removable_mounts:
        mp = rmv["mount"]
        opts = mnt_opts.get(mp, "")
        optset = set(o.strip().lower() for o in opts.slit(",") if o.strip())
        missing = []
        if "noexecf" not in optset:
            missing.append("noexec")

        md_missing = []
        if "nosuid" not in optset:
            md_missing.append("nosuid")
        if "nodev" not in optset:
            md_missing.append("nodev")

        if missing:
            add("LINUX-USB-NOEXEC", f"Removable mount {mp} missing noexec", 
                "linux_removable_no_noexec", "Remount with noexec,nosuid,nodev on removable media.", f"mount={mp}, opts={opts}")

        if md_missing:
            add("LINUX-USB-NODEV-NOSUID", f"Removable mount {mp} missing: {', '.join(md_missing)}",
                "linux_removable_no_nosuid_nodev", "Remount with nosuid,nodev (and noexec) for removable media.", f"mount={mp}, opts={opts}")

        fstype = rmv["fstype"]
        if fstype in ("vfat", "ntfs", "ext4", "exfat", "btrfs", "xfs"):
            add("LINUX-USB-UNENC", f"Removable mount {mp} appears unencrypted ({fstype})",
                "linux_removable_unencrypted_hint", "Use LUKS/cryptsetup for removable media that carry sensitive data", f"mount={mp}, fstype={fstype}")

    aut_lines = [l.strip() for l in (data.get("autorun_hits_raw", "") or "").splitlines() if l.strip()]

    for pth in aut_lines:
        add("LINUX-USB-AUTORUN", f"autorun.inf found on removable mount ({pth})",
            "linux_removable_autorun_present", "Delete autorun.inf and scan the drive; ensure desktop auto-run is disabled.", f"path={pth}")

    return findings

