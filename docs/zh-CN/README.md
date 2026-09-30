# Spec-Guardian 中文文档

**Spec-Guardian —— 开源仓库元数据与工程健康审计工具。不是代码 linter。**

> 它检查的是「仓库作为开源产物是否规范、能否被别人顺利复现、文档与发布有没有明显硬伤」，
> 而不是你的业务代码逻辑或安全漏洞。

- 英文主文档：[`../../README.md`](../../README.md)
- 规则清单（英文）：[`../rules.md`](../rules.md)
- 规则清单（中文）：[`rules.md`](rules.md)

---

## 它做什么 / 不做什么

### 它做

- 审计仓库根目录文件：`LICENSE`、`.gitignore`、`README`、社区文件。
- 检查 README 基线：快速开始、最低依赖版本、项目用途、已知限制。
- 扫描文档中的 `http(s)` 死链（可选用 WayBack Machine 给出存档替代）。
- 仅凭静态证据审计**构建与发布可复现性**：构建脚本、锁定文件、从源码构建说明、
  Release 校验和与二进制产物。
- 通过文件名与简单熵启发式，发现**明显误提交的危险文件**（`.env`、`*.pem`、`*.key` 等）。
- 提供**可配置的 YAML 规则引擎**（禁用规则、修改等级、新增自定义规则）。
- 输出 **JSON / 彩色终端 / 单文件 HTML** 三种报告，并可生成 `--fix-preview` 修复补丁预览。
- 作为 **GitHub Action** 开箱即用，自动上传 HTML 报告产物。

### 它不做

- ❌ 不做代码语法、风格、逻辑检查（那是 linter 的事）。
- ❌ 不做安全漏洞静态分析（SAST），请用 **gosec / semgrep / CodeQL**。
- ❌ 不做深度密钥扫描，请用 **gitleaks / trufflehog**。我们只做基础启发式警告。
- ❌ 不强制某种「唯一正确」的开源风格，所有规则均可开关、可覆写。
- ❌ **不修改、不 commit、不 push** 你的仓库。
- ❌ 不是 SaaS，不需要服务器；`--offline` 可完全离线运行。

---

## 安装

```sh
# macOS / Linux：单文件静态二进制，无运行时依赖
curl -fsSL https://raw.githubusercontent.com/wangzi5151/spec-guardian/main/install.sh | sh -s -- -b /usr/local/bin

# Windows
winget install wangzi5151.spec-guardian

# 从源码（Go >= 1.22）
go install github.com/wangzi5151/spec-guardian/cmd/spec-guardian@latest
```

## 快速开始

```sh
spec-guardian scan .                       # 扫描当前目录
spec-guardian scan /path/to/repo           # 扫描本地路径
spec-guardian scan --repo https://github.com/owner/repo   # 浅克隆远程仓库并扫描
spec-guardian scan . --format html         # 生成单文件 HTML 报告
spec-guardian scan . --offline             # 离线：不发起任何网络请求
spec-guardian scan . --fail-on medium      # 中危及以上即返回非零退出码
spec-guardian scan . --fix-preview fix.patch   # 仅生成补丁预览，不改动文件
spec-guardian export-rules --out specguard-rules.yml   # 导出规则模板
spec-guardian rules                        # 列出所有规则
```

## 退出码

| 退出码 | 含义 |
|--------|------|
| `0` | 高/中危全部通过，无阻断性问题 |
| `1` | 存在至少一条 **high** 级违规（默认让 PR 失败） |
| `2` | 仅有 `medium` / `low` / `info`，不阻断 |
| `3` | 运行时错误（参数错误、路径不可读、严格网络失败等） |

可用 `--fail-on high|medium|low|none` 调整阈值。

## 配置 `specguard-rules.yml`

```yaml
version: 1
settings:
  offline: false
  fail_on: high
  exclude: [vendor/**, node_modules/**]
  link_check:
    enabled: true
    concurrency: 8
    timeout_seconds: 10

rules:
  repo.readme.limitations:
    severity: info
  security.large_files:
    enabled: false

severity_overrides:
  docs.links.dead: high

disabled_rules: [community.codeowners]

custom_rules:
  - id: custom.no_todo_in_docs
    severity: low
    description: 文档中不允许 TODO
    message: 发现 TODO 标记
    type: regex
    pattern: "TODO"
    files: ["**/*.md"]
```

`custom_rules` 是「规则市场」的底层骨架：第三方可以只发布 YAML 规则集，
无需重新编译二进制。

## GitHub Action 接入

```yaml
name: spec-guardian
on: [pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: wangzi5151/spec-guardian@v0.1
        with:
          rules: specguard-rules.yml
          fail-on: high
```

Action 会把精简结果写入 workflow step summary，并把 HTML 报告上传为名为
`spec-guardian-report` 的 artifact。

## 内存与网络行为

- 只保存文件的元数据（路径、大小），内容按需流式读取，扫描上千个 Markdown 文件
  也不会把全部内容载入内存。
- 链接检查默认 8 并发、每主机 2 并发，带超时，避免对目标站点造成压力。
- `--offline` 时完全不做任何网络请求。

## 常见问题

**为什么不做代码漏洞扫描？**
那是完全不同、也更难的问题，已有成熟工具。Spec-Guardian 刻意保持窄范围，
让结果可信、噪声低。深度密钥扫描明确交给 gitleaks。

**它会替代 linter 吗？**
不会。linter 分析*代码*，Spec-Guardian 分析*仓库作为开源交付物*是否规范。

**会修改我的文件吗？**
默认绝不。`--fix-preview` 只会把建议写成一个 `.patch` 文件供你审阅，工具
从不改动工作区、从不 commit 或 push。

**需要 Docker 吗？**
不需要。发布的是无依赖的单文件静态二进制。
