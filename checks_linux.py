import subprocess, re
import json as _json


def _sh(cmd: str) -> tuple[bool, str]:
    try:
        out = subprocess.check_output(["bash", "-lc", cmd], stderr=subprocess.STDOUT, text=True, timeout=30)
        return True, out.strip()
    except Exception as e:
        return False, f"ERR: {e}"


def scan_localhost_top_ports(ports):
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
