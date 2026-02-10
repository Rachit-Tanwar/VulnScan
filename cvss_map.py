
def map_config_to_cvss(key: str, value):
    table = {
        # Windows posture
        "windows_defender_realtime_off":   (6.5, "High"),
        "windows_defender_tamper_off":     (6.2, "High"),
        "windows_defender_sig_old":        (6.0, "High"),
        "windows_firewall_partial_off":    (7.5, "High"),
        "windows_rdp_enabled":             (9.0, "Critical"),
        "windows_rdp_nla_disabled":        (8.2, "High"),
        "windows_smb1_enabled":            (9.8, "Critical"),
        "windows_min_passlen_lt12":        (5.3, "Medium"),
        "windows_guest_enabled":           (6.8, "High"),
        "windows_unexpected_local_admin":  (7.0, "High"),

        # Windows listening exposure
        "windows_listen_rdp":              (9.0, "Critical"),
        "windows_listen_smb":              (8.5, "High"),
        "windows_listen_winrm_http":       (7.5, "High"),
        "windows_listen_winrm_https":      (7.0, "High"),
        "windows_listen_ftp":              (7.5, "High"),
        "windows_listen_telnet":           (8.0, "High"),
        "windows_listen_mysql":            (7.0, "High"),
        "windows_listen_postgres":         (7.0, "High"),
        "windows_listen_redis":            (8.0, "High"),
        "windows_listen_mongo":            (7.5, "High"),

        # Windows removable / external device risks
        "windows_usb_policy_permissive":   (6.5, "High"),
        "windows_removable_unencrypted":   (7.5, "High"),
        "windows_removable_no_protection": (6.5, "High"),
        "windows_removable_autorun_present": (6.8, "High"),

        # Linux posture
        "linux_permitroot_not_no":         (7.8, "High"),
        "linux_passwordauth_not_no":       (6.8, "High"),
        "linux_peritemptypasswords_yes":   (8.0, "High"),
        "linux_ssh_protocol1":             (7.0, "High"),
        "linux_host_firewall_off":         (7.5, "High"),
        "linux_updates_pending":           (4.0, "Medium"),
        "linux_min_passlen_lt12":          (5.3, "Medium"),

        # Linux listening exposure
        "linux_listen_ssh":                (7.0, "High"),
        "linux_listen_ftp":                (7.0, "High"),
        "linux_listen_telnet":             (8.0, "High"),
        "linux_listen_smb":                (7.5, "High"),
        "linux_listen_mysql":              (7.0, "High"),
        "linux_listen_postgres":           (7.0, "High"),
        "linux_listen_redis":              (8.0, "High"),
        "linux_listen_mongo":              (7.5, "High"),
        "linux_listen_vnc":                (7.0, "High"),

        # Linux removable / external device risks
        "linux_removable_no_noexec":       (6.0, "High"),
        "linux_removable_no_nosuid_nodev": (5.5, "Medium"),
        "linux_removable_unencrypted_hint":(6.5, "High"),
        "linux_removable_autorun_present": (6.8, "High"),
    }
    return table.get(key, (4.0, "Medium"))
