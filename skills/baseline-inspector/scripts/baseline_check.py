#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""baseline-inspector — 只读的系统安全基线核查。

零依赖，只用 Python 3 标准库。

用法:
    python baseline_check.py
    python baseline_check.py --json
    python baseline_check.py --md baseline.md
    python baseline_check.py --fail-on high --only win-uac --only win-smb1
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
VERSION_FILE = ROOT / "VERSION"

STATUS_ORDER = {"FAIL": 0, "REVIEW": 1, "PASS": 2, "SKIP": 3}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SEVERITY_LABEL = {"high": "high", "medium": "medium", "low": "low"}


def get_version() -> str:
    try:
        return VERSION_FILE.read_text(encoding="utf-8").strip() or "0.0.0"
    except OSError:
        return "0.0.0"


def make_result(check_id, title, severity, status, current="", expected="", fix="", detail=""):
    return {
        "id": check_id,
        "title": title,
        "severity": severity,
        "status": status,
        "current": str(current),
        "expected": str(expected),
        "fix": fix,
        "detail": detail,
    }


def run(cmd, timeout=25):
    """执行只读查询命令，返回 (returncode, stdout, stderr)"""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return proc.returncode, (proc.stdout or "").strip(), (proc.stderr or "").strip()
    except Exception as exc:  # noqa: BLE001 - 查询失败统一降级为 REVIEW
        return None, "", str(exc)


def parse_bool(value):
    text = str(value).strip().lower()
    if text in ("true", "1", "yes"):
        return True
    if text in ("false", "0", "no"):
        return False
    return None


# ---------------------------------------------------------------- Windows

def windows_checks():
    import winreg

    hklm = winreg.HKEY_LOCAL_MACHINE

    def reg(path, name):
        try:
            with winreg.OpenKey(hklm, path) as key:
                return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    results = []

    uac = reg(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "EnableLUA")
    results.append(make_result(
        "win-uac", "UAC 用户账户控制", "high",
        "PASS" if uac == 1 else ("FAIL" if uac == 0 else "REVIEW"),
        f"EnableLUA={uac}", "EnableLUA=1",
        "在本地安全策略中启用 UAC，并设置提示级别不低于默认值。",
    ))

    smb1 = reg(r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1")
    results.append(make_result(
        "win-smb1", "SMBv1 协议", "high",
        "PASS" if smb1 == 0 else ("FAIL" if smb1 == 1 else "REVIEW"),
        f"SMB1={smb1}", "SMB1=0",
        "通过「启用或关闭 Windows 功能」禁用 SMB 1.0，重启后复查。",
        "" if smb1 is not None else "未显式配置，部分新系统默认禁用，需人工确认。",
    ))

    deny_rdp = reg(r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    if deny_rdp == 1:
        results.append(make_result(
            "win-rdp-nla", "RDP 网络级认证", "medium",
            "PASS", "RDP 已关闭", "RDP 关闭或启用 NLA",
            "如无需远程桌面，保持关闭。",
        ))
    else:
        nla = reg(
            r"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "UserAuthentication",
        )
        results.append(make_result(
            "win-rdp-nla", "RDP 网络级认证", "medium",
            "PASS" if nla == 1 else ("FAIL" if nla == 0 else "REVIEW"),
            f"UserAuthentication={nla}", "UserAuthentication=1",
            "在系统属性 → 远程中勾选「仅允许运行使用网络级别身份验证的远程桌面」。",
        ))

    profiles = {
        "域": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile",
        "专用": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile",
        "公用": r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile",
    }
    firewall_values = {name: reg(path, "EnableFirewall") for name, path in profiles.items()}
    if all(value == 1 for value in firewall_values.values()):
        fw_status, fw_detail = "PASS", ""
    elif any(value == 0 for value in firewall_values.values()):
        fw_status, fw_detail = "FAIL", ""
    else:
        fw_status, fw_detail = "REVIEW", "部分配置文件未读取到值。"
    results.append(make_result(
        "win-firewall", "Windows 防火墙", "high",
        fw_status,
        ", ".join(f"{k}={v}" for k, v in firewall_values.items()),
        "三个配置文件均 EnableFirewall=1",
        "在 Windows 安全中心启用域、专用、公用三种配置文件的防火墙。",
        fw_detail,
    ))

    rc, out, err = run([
        "powershell", "-NoProfile", "-Command",
        "(Get-MpComputerStatus).RealTimeProtectionEnabled | ConvertTo-Json",
    ])
    defender = parse_bool(out)
    results.append(make_result(
        "win-defender", "Defender 实时防护", "high",
        "PASS" if defender is True else ("FAIL" if defender is False else "REVIEW"),
        out or err[:80] or "未获取", "True",
        "启用 Microsoft Defender 实时保护；若使用第三方杀软，确认其处于托管状态。",
        "" if defender is not None else "命令执行失败或权限不足。",
    ))

    rc, out, err = run([
        "powershell", "-NoProfile", "-Command",
        "$g = Get-LocalUser -Name Guest -ErrorAction SilentlyContinue; "
        "if ($g) { $g.Enabled } else { 'absent' }",
    ])
    guest_text = out.strip().lower()
    if guest_text == "absent" or guest_text == "false":
        guest_status = "PASS"
    elif guest_text == "true":
        guest_status = "FAIL"
    else:
        guest_status = "REVIEW"
    results.append(make_result(
        "win-guest", "Guest 账户", "medium",
        guest_status, out or err[:80] or "未获取", "禁用或不存在",
        "在「本地用户和组」中禁用 Guest 账户。",
    ))

    policy = {"MinimumPasswordLength": None, "LockoutBadCount": None}
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            inf_path = Path(tmpdir) / "secpol.inf"
            run(["secedit", "/export", "/cfg", str(inf_path), "/quiet"], timeout=30)
            if inf_path.exists():
                raw = inf_path.read_bytes()
                for encoding in ("utf-16", "utf-16-le", "utf-8", "gbk"):
                    try:
                        text = raw.decode(encoding)
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    text = ""
                for line in text.splitlines():
                    if "=" not in line:
                        continue
                    key, _, value = line.partition("=")
                    key = key.strip()
                    if key in policy:
                        try:
                            policy[key] = int(value.strip())
                        except ValueError:
                            pass
    except Exception:
        pass

    min_len = policy["MinimumPasswordLength"]
    lockout = policy["LockoutBadCount"]
    if min_len is None or lockout is None:
        pw_status, pw_detail = "REVIEW", "未能导出安全策略，可能权限不足。"
    elif min_len >= 8 and 1 <= lockout <= 5:
        pw_status, pw_detail = "PASS", ""
    else:
        pw_status, pw_detail = "FAIL", ""
    results.append(make_result(
        "win-password-policy", "密码与锁定策略", "high",
        pw_status,
        f"最小长度={min_len}, 锁定阈值={lockout}",
        "最小长度>=8, 锁定阈值 1-5",
        "在本地安全策略中调整密码长度与账户锁定策略。",
        pw_detail,
    ))
    return results


# ---------------------------------------------------------------- Linux

def read_sshd_config():
    path = Path("/etc/ssh/sshd_config")
    if not path.is_file():
        return None
    config = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            config[parts[0].lower()] = parts[1].strip()
    return config


def linux_checks():
    results = []
    config = read_sshd_config()
    if config is None:
        for check_id, title, severity in (
            ("linux-ssh-root", "SSH 禁止 root 登录", "high"),
            ("linux-ssh-password", "SSH 禁用密码登录", "high"),
            ("linux-ssh-maxauth", "SSH 最大认证尝试次数", "medium"),
        ):
            results.append(make_result(
                check_id, title, severity, "REVIEW",
                "未找到 /etc/ssh/sshd_config", "", "确认是否安装并启用了 SSH 服务。",
            ))
    else:
        root_login = config.get("permitrootlogin", "prohibit-password")
        results.append(make_result(
            "linux-ssh-root", "SSH 禁止 root 登录", "high",
            "PASS" if root_login.lower() == "no" else "FAIL",
            f"PermitRootLogin={root_login}", "no",
            "设置 PermitRootLogin no 并重启 sshd。",
        ))
        password_auth = config.get("passwordauthentication", "yes")
        results.append(make_result(
            "linux-ssh-password", "SSH 禁用密码登录", "high",
            "PASS" if password_auth.lower() == "no" else "FAIL",
            f"PasswordAuthentication={password_auth}", "no",
            "改用密钥登录，设置 PasswordAuthentication no 并重启 sshd。",
        ))
        max_auth = config.get("maxauthtries")
        if max_auth is None:
            results.append(make_result(
                "linux-ssh-maxauth", "SSH 最大认证尝试次数", "medium",
                "REVIEW", "未配置（默认 6）", "<=4",
                "设置 MaxAuthTries 4 并重启 sshd。",
            ))
        else:
            try:
                auth_ok = int(max_auth) <= 4
            except ValueError:
                auth_ok = False
            results.append(make_result(
                "linux-ssh-maxauth", "SSH 最大认证尝试次数", "medium",
                "PASS" if auth_ok else "FAIL",
                f"MaxAuthTries={max_auth}", "<=4",
                "设置 MaxAuthTries 4 并重启 sshd。",
            ))

    shadow = Path("/etc/shadow")
    if shadow.exists():
        try:
            mode = stat.S_IMODE(shadow.stat().st_mode)
            results.append(make_result(
                "linux-shadow-perm", "/etc/shadow 文件权限", "high",
                "PASS" if mode & 0o077 == 0 else "FAIL",
                oct(mode), "600 或 640",
                "chmod 640 /etc/shadow 并确认属组为 shadow。",
            ))
            empty_users = []
            for line in shadow.read_text(encoding="utf-8", errors="replace").splitlines():
                fields = line.split(":")
                if len(fields) >= 2 and fields[1] == "":
                    empty_users.append(fields[0])
            results.append(make_result(
                "linux-empty-password", "空密码账户", "high",
                "FAIL" if empty_users else "PASS",
                "、".join(empty_users) if empty_users else "无",
                "无空密码账户",
                "为相关账户设置强密码或锁定账户。",
            ))
        except PermissionError:
            results.append(make_result(
                "linux-empty-password", "空密码账户", "high",
                "REVIEW", "无读取权限", "无空密码账户",
                "使用 root 或 sudo 运行。",
            ))
    else:
        results.append(make_result(
            "linux-shadow-perm", "/etc/shadow 文件权限", "high",
            "SKIP", "文件不存在", "600 或 640", "非本地用户库环境，跳过。",
        ))

    firewall_status = "REVIEW"
    firewall_current = "未检测到 ufw / firewalld"
    if shutil.which("ufw"):
        rc, out, _ = run(["ufw", "status"])
        if "status: active" in (out or "").lower():
            firewall_status, firewall_current = "PASS", "ufw active"
        elif out:
            firewall_status, firewall_current = "FAIL", "ufw inactive"
    elif shutil.which("systemctl"):
        rc, out, _ = run(["systemctl", "is-active", "firewalld"])
        if out.strip() == "active":
            firewall_status, firewall_current = "PASS", "firewalld active"
        elif out.strip() in ("inactive", "failed"):
            firewall_status, firewall_current = "FAIL", f"firewalld {out.strip()}"
    results.append(make_result(
        "linux-firewall", "主机防火墙", "high",
        firewall_status, firewall_current, "ufw 或 firewalld 处于 active",
        "启用并配置 ufw 或 firewalld，默认拒绝入站。",
    ))
    return results


def collect_results(platform_name):
    if platform_name == "Windows":
        return windows_checks()
    if platform_name == "Linux":
        return linux_checks()
    return [make_result(
        "unsupported-platform", "平台支持", "low", "REVIEW",
        platform_name or "unknown", "Windows 或 Linux",
        "当前平台没有内置检查项。",
    )]


# ---------------------------------------------------------------- 输出

def sort_results(results):
    return sorted(
        results,
        key=lambda r: (STATUS_ORDER.get(r["status"], 9), SEVERITY_ORDER.get(r["severity"], 9), r["id"]),
    )


def print_text(meta, results):
    print(f"baseline-inspector {meta['version']} · {meta['os']}")
    print(f"主机: {meta['hostname']} | 时间: {meta['time']}\n")
    for item in results:
        print(f"[{item['status']}] [{item['severity']}] {item['title']}")
        if item["status"] != "PASS":
            print(f"       当前: {item['current']} | 期望: {item['expected']}")
            if item["fix"]:
                print(f"       修复: {item['fix']}")
            if item["detail"]:
                print(f"       说明: {item['detail']}")
    counts = {status: 0 for status in STATUS_ORDER}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    print(
        f"\n汇总: PASS {counts.get('PASS', 0)} / FAIL {counts.get('FAIL', 0)} / "
        f"REVIEW {counts.get('REVIEW', 0)} / SKIP {counts.get('SKIP', 0)}"
    )


def build_markdown(meta, results):
    lines = [
        "# 基线核查报告",
        "",
        f"- 主机：{meta['hostname']}",
        f"- 系统：{meta['os']}",
        f"- 时间：{meta['time']}",
        f"- 工具版本：{meta['version']}",
        "",
        "## 汇总",
        "",
        "| PASS | FAIL | REVIEW | SKIP |",
        "| ---: | ---: | ---: | ---: |",
    ]
    counts = {status: 0 for status in STATUS_ORDER}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    lines.append(
        f"| {counts.get('PASS', 0)} | {counts.get('FAIL', 0)} "
        f"| {counts.get('REVIEW', 0)} | {counts.get('SKIP', 0)} |"
    )
    lines += [
        "",
        "## 明细",
        "",
        "| ID | 级别 | 状态 | 检查项 | 当前 | 期望 | 修复建议 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in results:
        cells = [
            item["id"], item["severity"], item["status"], item["title"],
            item["current"], item["expected"], item["fix"],
        ]
        lines.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in cells) + " |")
    lines += ["", "> 本报告只读生成，未修改任何系统配置。"]
    return "\n".join(lines).rstrip() + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="只读的系统安全基线核查")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--md", metavar="FILE", help="生成 Markdown 报告")
    parser.add_argument(
        "--fail-on", choices=["high", "medium", "none"], default="high",
        help="达到该级别的 FAIL 时返回非零，默认 high",
    )
    parser.add_argument("--only", action="append", default=[], help="只跑指定检查 ID，可多次指定")
    parser.add_argument("--version", action="version", version=f"%(prog)s {get_version()}")
    args = parser.parse_args(argv)

    platform_name = platform.system()
    meta = {
        "version": get_version(),
        "hostname": platform.node() or "unknown",
        "os": f"{platform_name} {platform.release()}".strip(),
        "python": platform.python_version(),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    results = sort_results(collect_results(platform_name))
    if args.only:
        wanted = {item.lower() for item in args.only}
        results = [item for item in results if item["id"].lower() in wanted]
        if not results:
            print(f"[!] 没有匹配的检查项: {', '.join(sorted(wanted))}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps({"meta": meta, "results": results}, ensure_ascii=False, indent=2))
    else:
        print_text(meta, results)

    if args.md:
        Path(args.md).write_text(build_markdown(meta, results), encoding="utf-8")
        if not args.json:
            print(f"[已写入] {args.md}", file=sys.stderr)

    if args.fail_on == "none":
        return 0
    threshold = SEVERITY_ORDER[args.fail_on]
    failing = [
        item for item in results
        if item["status"] == "FAIL" and SEVERITY_ORDER.get(item["severity"], 9) <= threshold
    ]
    return 1 if failing else 0


if __name__ == "__main__":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except AttributeError:
        pass
    raise SystemExit(main())
