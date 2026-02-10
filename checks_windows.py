import subprocess, tempfile, os, re, json

APPROVED_LOCAL_ADMINS = {"Administrator"}

def _ps(cmd: str) -> tuple[bool, str]:
    try:
        out = subprocess.check_output(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", cmd],
        stderr=subprocess.STDOUT, text=True, timeout=40
        )
        return True, out.strip()
    except Exception as e:
        return False, f"ERR: {e}"


def _read_text_any(path):
    for enc in ("utf-16", "utf-16le", "utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except Exception:
            continue
    return ""


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
                s.close()
            except:
                pass
    return open_ports


def gather() -> dict:
    ok, osinfo = _ps("(Get-CimInstance Win32_OperatingSystem | Select Caption, Version, Build Number) | ConvertTo-Json -Depth 4")
    ok_d, definfo = _ps("Get-MpComputerStatus | Select AMServiceEnabled,AntispywareEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,IsTamperProtected | ConvertTo-Json")
    ok_f, fwinfo = _ps("Get-NetFirewallProfile | Select Name, Enabled | ConvertTo-Json")
    ok_r, rdp = _ps("(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server').fDenyTSConnections")
    ok_nla, nla = _ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication")
    ok_s, smb = _ps("Get-SmbServerConfiguration | Select EnableSMB1Protocol | ConvertTo-Json")

    sec_tmp = os.path.join(tempfile.gettempdir(), "secpol.cfg")
    _ps(f"secedit /export /cfg '{sec_tmp}' | Out-Null")
    sec_txt = _read_text_any(sec_tmp)

    ok_a, admins = _ps("Get-LocalGroupMember -Group 'Administrators' | Select-Object -ExpandProperty Name | ConvertTo-Json")
    ok_g, guest = _ps("(Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue).Enabled")

    ok_p, ports_json = _ps("Get-NetTCPConnection -State Listen | Select-Object -ExpandProperty LocalPort | Sort-Object -Unique | ConvertTo-Json")

    sig_age_days = None
    if ok_d and "AntivirusSignatureLastUpdated" in definfo:
        m = re.search(r"AntivirusSignatureLastUpdated\"\s*:\s*\"([^\"]+)\"", definfo)
        if m:
            from datetime import datetime, timezone
            try:
                d = datetime.fromisoformat(m.group(1).replace('Z','+00:00'))
                sig_age_days = (datetime.now(timezone.utc) - d).days
            except Exception:
                pass

    active_ports = _scan_localhost_top_ports([21,22,23,80,443,445,139,3389,5985,5986,3306,5432,6379,27017,5900])

    ok_usb, usb_disks = _ps("(Get-CimInstance Win32_DiskDrive | Where-Object {$_.InterfaceType -eq 'USB'}) | "
                            "Select-Object DeviceID,Model,Size | ConvertTo-Json -Depth 3")

    ok_vol, vols = _ps("(Get-Volume | Where-Object {$_.DriveType -eq 'Removable'}) | "
                       "Select-Object DriveLetter,FileSystem,FriendlyName,Path,Size,SizeRemaining | ConvertTo-Json -Depth 3")

    ok_bl, bl = _ps("Get-BitLockerVolume | Select-Object MountPoint,VolumeType,ProtectionStatus,EncryptionMethod | ConvertTo-Json -Depth 4")

    ok_pol1, usbstor = _ps("(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -ErrorAction SilentlyContinue).Start")

    ok_pol2, rds_pol = _ps("Get-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\RemovableStorageDevices' -ErrorAction SilentlyContinue | "
                           "Select -ExpandProperty Property | ConvertTo-Json -Depth 3")

    ok_ar, autoruns = _ps("(Get-Volume | Where-Object {$_.DriveType -eq 'Removable' -and $_.DriveLetter}) | "
                          "ForEach-Object { $d = ($_.DriveLetter + ':\'); "
                          "if (Test-Path ($d + 'autorun.inf')) { $d + 'autorun.inf' } } | ConvertTo-Json")

    return {
        "platform": "windows",
        "os_detail": osinfo if ok else osinfo,
        "defender_raw": definfo if ok_d else definfo,
        "firewall_raw": fwinfo if ok_f else fwinfo,
        "rdp_deny_val": rdp.strip() if ok_r else rdp,
        "nla_val": nla.strip() if ok_nla else nla,
        "smb1_raw": smb if ok_s else smb,
        "secpol_txt": sec_txt,
        "admins_raw": admins if ok_a else admins,
        "guest_enabled_raw": guest.strip() if ok_g else guest,
        "def_sig_age_days": sig_age_days,
        "listening_ports_raw": ports_json if ok_p else ports_json,
        "active_ports": active_ports,

        "usb_disks_raw": usb_disks if ok_usb else usb_disks,
        "removable_volumes_raw": vols if ok_vol else vols,
        "bitlocker_raw": bl if ok_bl else bl,
        "usbstor_start": usbstor.strip() if ok_pol1 else usbstor,
        "removable_policy_raw": rds_pol if ok_pol2 else rds_pol,
        "autorun_hits_raw": autoruns if ok_ar else autoruns,
    }

def analyze(data: dict) -> list[dict]:
    from cvss_map import map_config_to_cvss
    findings = []

    def add(id_, title, key, remediation, evidence):
        cvss, sev = map_config_to_cvss(key, None)
        findings.append({"id":id_, "title":title, "cvss":cvss, "severity":sev,
                         "remediation":remediation, "evidence":evidence})

    defraw = data.get("defender_raw","")
    def_on = ("\"RealTimeProtectionEnabled\":  true" in defraw) or ("\"RealTimeProtectionEnabled\":true" in defraw)
    tamper_on = ("\"IsTamperProtected\":  true" in defraw) or ("\"IsTamperProtected\":true" in defraw)
    if not def_on:
        add("WIN-DEF-RT","Defender real-time protection is OFF",
            "windows_defender_realtime_off","Enable Microsoft Defender Real-Time Protection.", defraw[:800])
    if not tamper_on:
        add("WIN-DEF-TAMPER","Defender tamper protection is OFF",
            "windows_defender_tamper_off","Enable Defender Tamper Protection.", defraw[:800])

    sig_age_days = data.get("def_sig_age_days")
    if isinstance(sig_age_days, int) and sig_age_days > 7:
        add("WIN-DEF-SIG","Defender AV signatures are stale (>7 days old)",
            "windows_defender_sig_old","Update Defender signatures.", f"sig_age_days={sig_age_days}")

    fwraw = data.get("firewall_raw","")
    profiles_on = fwraw.count("\"Enabled\":  1") + fwraw.count("\"Enabled\":1")
    if profiles_on < 3:
        add("WIN-FW","Windows Firewall not enabled for all profiles",
            "windows_firewall_partial_off","Enable Firewall for Domain, Private & Public profiles.", fwraw[:800])

    rdp_raw = str(data.get("rdp_deny_val","")).strip()
    rdp_enabled = (rdp_raw == "0")
    if rdp_enabled:
        add("WIN-RDP","Remote Desktop (RDP) is enabled",
            "windows_rdp_enabled","Disable RDP if not required; otherwise restrict via VPN + Firewall + NLA.", f"fDenyTSConnections={rdp_raw}")
        nla_raw = str(data.get("nla_val","")).strip()
        nla_on = (nla_raw == "1")
        if not nla_on:
            add("WIN-RDP-NLA","RDP Network Level Authentication (NLA) is disabled",
                "windows_rdp_nla_disabled","Enable NLA (System Properties > Remote > allow connections only with NLA).", f"UserAuthentication={nla_raw}")

    smbraw = data.get("smb1_raw","")
    smb1_on = ("\"EnableSMB1Protocol\":  true" in smbraw) or ("\"EnableSMB1Protocol\":true" in smbraw)
    if smb1_on:
        add("WIN-SMB1","SMBv1 protocol is enabled (deprecated & insecure)",
            "windows_smb1_enabled","Disable SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false).", smbraw[:800])

    sec = data.get("secpol_txt","")
    m = re.search(r"MinimumPasswordLength\s*=\s*(\d+)", sec)
    if m:
        minlen = int(m.group(1))
        if minlen < 12:
            add("WIN-PASSLEN", f"Minimum password length is {minlen} (<12)",
                "windows_min_passlen_lt12","Set minimum password length to at least 12.", f"MinimumPasswordLength={minlen}")

    admins_raw = data.get("admins_raw","")
    members = []
    if admins_raw.strip().startswith("["):
        try:
            members = json.loads(admins_raw)
        except Exception:
            members = [admins_raw]
    else:
        members = [a.strip() for a in admins_raw.splitlines() if a.strip()]
    unexpected = [m for m in members if m not in APPROVED_LOCAL_ADMINS]
    for u in unexpected:
        add("WIN-ADM-UNEXP", f"Unexpected local Administrator: {u}",
            "windows_unexpected_local_admin","Review Administrators group and remove non-approved accounts.", f"member={u}")

    guest_raw = str(data.get("guest_enabled_raw","")).strip().lower()
    if guest_raw == "true":
        add("WIN-GUEST","Guest account is enabled",
            "windows_guest_enabled","Disable the Guest account.", f"Guest.Enabled={guest_raw}")

    ports_raw = data.get("listening_ports_raw","")
    listen = []
    if isinstance(ports_raw, str) and ports_raw.strip().startswith("["):
        try:
            listen = sorted({int(p) for p in json.loads(ports_raw) if str(p).isdigit()})
        except Exception:
            pass
    for p in data.get("active_ports", []):
        if p not in listen: listen.append(p)

    risky = {
        3389: ("WIN-NET-RDP-LISTEN","RDP port 3389 is listening","windows_listen_rdp",
               "If RDP is required, restrict via VPN + Firewall + NLA; otherwise disable."),
        445:  ("WIN-NET-SMB-LISTEN","SMB port 445 is listening","windows_listen_smb",
               "Restrict SMB exposure; disable SMBv1; allow only trusted subnets."),
        139:  ("WIN-NET-NB-LISTEN", "NetBIOS port 139 is listening","windows_listen_smb",
               "Avoid legacy SMB/NetBIOS exposure; restrict via firewall."),
        5985: ("WIN-NET-WINRM-HTTP","WinRM HTTP (5985) is listening","windows_listen_winrm_http",
               "Prefer WinRM over HTTPS (5986) and restrict via firewall."),
        5986: ("WIN-NET-WINRM-HTTPS","WinRM HTTPS (5986) is listening","windows_listen_winrm_https",
               "Restrict WinRM to admin subnets and enforce auth."),
        21:   ("WIN-NET-FTP",       "FTP (21) is listening","windows_listen_ftp",
               "Avoid plain FTP; use FTPS/SFTP; restrict via firewall."),
        23:   ("WIN-NET-TELNET",    "Telnet (23) is listening","windows_listen_telnet",
               "Disable Telnet; use SSH; restrict via firewall."),
        3306: ("WIN-NET-MYSQL",     "MySQL (3306) is listening","windows_listen_mysql",
               "Bind to localhost/private VLAN; require strong auth; firewall."),
        5432: ("WIN-NET-POSTGRES",  "PostgreSQL (5432) is listening","windows_listen_postgres",
               "Bind to localhost/private VLAN; firewall; auth."),
        6379: ("WIN-NET-REDIS",     "Redis (6379) is listening","windows_listen_redis",
               "Never expose Redis publicly; require auth; firewall."),
        27017:("WIN-NET-MONGO",     "MongoDB (27017) is listening","windows_listen_mongo",
               "Bind to localhost/private VLAN; firewall; auth."),
        5900: ("WIN-NET-VNC",       "VNC (5900) is listening","windows_listen_winrm_http",
               "Restrict VNC via VPN/SSH tunnel; firewall off public access."),
        80:   ("WIN-NET-HTTP",      "HTTP (80) is listening","windows_listen_winrm_http",
               "Avoid exposing HTTP publicly; prefer HTTPS; firewall appropriately."),
        443:  ("WIN-NET-HTTPS",     "HTTPS (443) is listening","windows_listen_winrm_https",
               "Restrict exposure to required subnets; ensure TLS is strong."),
    }
    for p, (fid, title, key, rem) in risky.items():
        if p in listen:
            cvss, sev = map_config_to_cvss(key, None)
            findings.append({"id": fid, "title": title, "cvss": cvss, "severity": sev,
                             "remediation": rem, "evidence": f"listening_port={p}"})

    # Policy: USBSTOR service 'Start' value: 3 = enabled, 4 = disabled
    usbstor_val = str(data.get("usbstor_start","")).strip()
    try:
        usbstor_val_int = int(usbstor_val)
    except:
        usbstor_val_int = 3  # assume enabled if unknown
    if usbstor_val_int == 3:
        add("WIN-USB-POLICY", "USB mass storage allowed by policy",
            "windows_usb_policy_permissive",
            "Consider restricting USB storage (set USBSTOR Start=4 via GPO) on high-sensitivity PCs.",
            f"USBSTOR.Start={usbstor_val}")

    blraw = data.get("bitlocker_raw","")
    vols_raw = data.get("removable_volumes_raw","") or "[]"
    try:
        vols = json.loads(vols_raw) if vols_raw.strip().startswith("[") else []
    except:
        vols = []
    bl_list = []
    if isinstance(blraw, str) and blraw.strip().startswith("["):
        try: bl_list = json.loads(blraw)
        except: bl_list = []
    elif isinstance(blraw, str) and blraw.strip().startswith("{"):
        bl_list = [json.loads(blraw)]
    bl_map = {}
    for v in bl_list:
        mp = (v.get("MountPoint") or "").strip()
        prot = v.get("ProtectionStatus")
        bl_map[mp] = prot

    for v in vols:
        dl = v.get("DriveLetter")
        fs = (v.get("FileSystem") or "").upper()
        if not dl: 
            continue
        mp = f"{dl}:\\"
        prot = bl_map.get(mp, 0)
        if prot == 0:
            add("WIN-USB-NOENC", f"Removable drive {dl}: not protected by BitLocker",
                "windows_removable_unencrypted",
                "Enable BitLocker To Go for removable drives that may carry sensitive data.",
                f"MountPoint={mp}, FileSystem={fs}, ProtectionStatus={prot}")
        elif prot != 1:
            add("WIN-USB-NOPROT", f"Removable drive {dl}: BitLocker protection not confirmed ON",
                "windows_removable_no_protection",
                "Ensure BitLocker To Go protection is ON for removable drives.",
                f"MountPoint={mp}, FileSystem={fs}, ProtectionStatus={prot}")

    ar_raw = data.get("autorun_hits_raw","") or "[]"
    try:
        ar_list = json.loads(ar_raw) if ar_raw.strip().startswith("[") else []
    except:
        ar_list = []
    for pth in ar_list:
        add("WIN-USB-AUTORUN", f"autorun.inf found on removable drive ({pth})",
            "windows_removable_autorun_present",
            "Delete autorun.inf and scan the drive; ensure AutoRun is disabled via policy.",
            f"path={pth}")

    return findings
