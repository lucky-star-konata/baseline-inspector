---
name: baseline-inspector
description: Run a read-only security baseline check on a host. Use when hardening a server or workstation, verifying UAC/SMBv1/RDP/firewall/password policy on Windows, checking SSH and shadow file permissions on Linux, or producing a PASS/FAIL/REVIEW baseline report before an audit.
---

# baseline-inspector

对本机或已授权主机做只读基线核查，输出可复核的 PASS / FAIL / REVIEW 清单。

## 何时使用

- 新主机上线前做一次安全配置自查
- 等保 / CIS 基线整改前后对比
- 排查「为什么这台机器明显不合规」的常见项
- 把基线检查结果作为交付材料的一部分

## 前置条件

- 对目标主机有合法管理权限，或目标就是本机
- 脚本只读，不需要管理员权限也能跑，但部分项权限不足会返回 REVIEW

## 运行

```bash
python scripts/baseline_check.py
python scripts/baseline_check.py --json
python scripts/baseline_check.py --md baseline.md
python scripts/baseline_check.py --fail-on high
```

参数：

- `--json`：结构化输出，便于接入工单或 CI
- `--md FILE`：生成 Markdown 报告
- `--fail-on {high,medium,none}`：达到该级别的 FAIL 时退出码为 1，默认 `high`
- `--only ID`：只跑指定检查，可多次指定
- `--version`

## 检查项

**Windows**

| ID | 检查 | 期望 |
| --- | --- | --- |
| `win-uac` | UAC 开关 | `EnableLUA = 1` |
| `win-smb1` | SMBv1 | `SMB1 = 0` |
| `win-rdp-nla` | RDP 网络级认证 | `UserAuthentication = 1` 或 RDP 已关闭 |
| `win-firewall` | 防火墙三配置文件 | `EnableFirewall = 1` |
| `win-defender` | Defender 实时防护 | 开启 |
| `win-guest` | Guest 账户 | 禁用 |
| `win-password-policy` | 密码长度与锁定策略 | 长度 ≥ 8，锁定阈值 1–5 |

**Linux**

| ID | 检查 | 期望 |
| --- | --- | --- |
| `linux-ssh-root` | `PermitRootLogin` | `no` |
| `linux-ssh-password` | `PasswordAuthentication` | `no` |
| `linux-ssh-maxauth` | `MaxAuthTries` | ≤ 4 |
| `linux-shadow-perm` | `/etc/shadow` 权限 | 不含组/其他可读 |
| `linux-empty-password` | 空密码账户 | 不存在 |
| `linux-firewall` | ufw / firewalld | active |

## 输出契约

- 每条结果包含：ID、级别、状态、当前值、期望值、修复建议
- 状态只有四种：`PASS` / `FAIL` / `REVIEW` / `SKIP`
- 拿不到数据时返回 `REVIEW`，不默认判 PASS
- 退出码：存在达到 `--fail-on` 阈值的 FAIL 时为 1

## 红线

- 只读，不提供任何自动修复开关；修复必须人工执行并留变更记录
- 核查结果可能包含主机名、路径、策略值，不要提交到公开仓库
- 不在未授权主机上运行

## 坑点

- 权限不足时 `secedit` / `Get-MpComputerStatus` 会失败，属于 REVIEW 而非 PASS
- Linux 容器里没有 sshd、ufw、firewalld 时，相关项会返回 REVIEW
- 不同发行版默认值不同，判定以你所在组织的基线文档为准
