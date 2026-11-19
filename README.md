# baseline-inspector

只读的系统基线核查工具：检查主机安全配置是否符合基线要求，输出 PASS / FAIL / REVIEW 清单与修复建议，不改动任何配置。

> 用于自有主机或已授权资产的安全加固检查。详见 [DISCLAIMER.md](DISCLAIMER.md)。

## 能查什么

| 平台 | 检查项 |
| --- | --- |
| Windows | UAC、SMBv1、SMB 签名、不安全的来宾登录、RDP NLA、防火墙（域/专用/公用）、Defender 实时防护、Guest 账户、自动登录与明文密码、PowerShell 脚本块日志、密码策略 |
| Linux | SSH root 登录、SSH 密码登录、SSH MaxAuthTries、密码有效期与长度、默认 umask、/etc/crontab 权限、sudo NOPASSWD、/etc/shadow 权限、空密码账户、防火墙状态 |

所有检查均为只读：读注册表、读配置文件、执行查询类命令，不修改任何系统设置。

用 `--list-checks` 可以列出全部检查项 ID 与级别。

## 快速开始

```bash
python skills/baseline-inspector/scripts/baseline_check.py
python skills/baseline-inspector/scripts/baseline_check.py --json
python skills/baseline-inspector/scripts/baseline_check.py --md report.md
python skills/baseline-inspector/scripts/baseline_check.py --fail-on high
```

退出码：

- `0`：没有达到阈值的失败项
- `1`：存在达到阈值的失败项（默认 `high`）
- `2`：参数或运行错误

## 输出示例

```
baseline-inspector 1.0.0 · Windows 11 (10.0.22631)
[PASS] [high] UAC 已启用（EnableLUA=1）
[FAIL] [high] SMBv1 仍启用
       当前: SMB1=1 | 期望: 0
       修复: 禁用 SMBv1 功能，重启后复查
[REVIEW] [medium] 未获取到 Defender 实时防护状态
           需管理员权限或 Defender 被第三方接管
汇总: PASS 5 / FAIL 1 / REVIEW 1 / SKIP 0
```

## Skill 用法

```bash
cp -r skills/baseline-inspector ~/.claude/skills/
```

之后可以直接让 Agent「做一次基线核查」「看看这台机器有没有明显配置问题」。

## 设计原则

- **只读**：不提供任何修改开关，修复动作由人工执行
- **可复核**：每条结论附当前值、期望值和修复建议
- **零依赖**：只用 Python 标准库，Windows 走 `winreg`，Linux 读文件
- **不确定就 REVIEW**：拿不到数据时不猜 PASS，标记 REVIEW 交人工确认

## 已知限制

- 不是完整的等保/CIS 基线，只覆盖最常见的几项；规则扩展需要改脚本
- Windows 部分项依赖 PowerShell 或 `secedit`，权限不足时返回 REVIEW
- Linux 只适配常见发行版，容器环境下多数检查会返回 REVIEW

## License

[MIT](LICENSE)
