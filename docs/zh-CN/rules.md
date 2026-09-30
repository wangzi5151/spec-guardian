# Spec-Guardian 规则清单（中文）

每条规则都有稳定的 ID、默认严重等级（`high` / `medium` / `low` / `info`）和修复指引。
所有规则都可以在 `specguard-rules.yml` 中禁用或改级别。

> 等级是「审阅提示」，不是安全判决。`high` 表示「这通常会让陌生人难以使用你的项目」，
> 而**不是**「你存在安全漏洞」。

---

## 仓库根文件

| 规则 ID | 默认等级 | 检查内容 |
|---------|----------|----------|
| `repo.license.exists` | high | 根目录是否存在 `LICENSE` / `LICENCE` / `COPYING` |
| `repo.license.recognized` | medium | 许可证文本能否匹配内置 SPDX 库（MIT、Apache-2.0、GPL-3.0…） |
| `repo.license.year` | info | 版权年份范围是否合理（仅提示） |
| `repo.license.header_comments` | low（可选） | 源码文件头部版权/SPDX 注释覆盖率（`settings.header_comment_check: true` 开启） |
| `repo.gitignore.exists` | medium | 根目录是否存在 `.gitignore` |
| `repo.gitignore.risk_patterns` | medium（按条目） | 是否覆盖 `.env`、`*.pem`、`*.key`、`node_modules/`、`*.log`、`.DS_Store`、`dist/` |

## 文档

| 规则 ID | 默认等级 | 检查内容 |
|---------|----------|----------|
| `repo.readme.exists` | high | 是否存在 README |
| `repo.readme.quickstart` | high | 是否有含可执行命令的快速开始/安装/使用区块 |
| `repo.readme.dependencies` | medium | 是否写明最低依赖/工具链版本（如 `Go >= 1.22`） |
| `repo.readme.description` | medium | 顶部是否有一句话项目用途描述 |
| `repo.readme.limitations` | info | 是否有已知限制/注意事项段落 |
| `docs.links.dead` | medium | Markdown 中的 `http(s)` 链接是否存活（`--offline` 时跳过） |
| `docs.links.archived` | info | 死链在 WayBack Machine 是否有存档替代 |

## 社区文件

| 规则 ID | 默认等级 | 检查内容 |
|---------|----------|----------|
| `community.contributing` | info | 是否有 `CONTRIBUTING.md` |
| `community.codeowners` | info | 是否有 `CODEOWNERS` |
| `community.security` | medium | 是否有 `SECURITY.md` |
| `community.issue_template` | info | `.github/ISSUE_TEMPLATE/` 是否存在 |
| `community.pr_template` | info | 是否有 PR 模板 |

## 构建与可复现性

| 规则 ID | 默认等级 | 检查内容 |
|---------|----------|----------|
| `build.script.exists` | medium | 是否有可发现的构建定义（Makefile、justfile、Taskfile、package.json scripts、meson.build、Cargo.toml、go.mod…） |
| `build.from_source_documented` | medium | 是否有「如何从源码重新构建 Release 产物」的文档说明 |
| `build.lockfile.exists` | medium | 对应生态的锁定文件是否存在（go.sum、package-lock.json、Cargo.lock、poetry.lock…） |
| `release.checksums` | medium（仅 GitHub 远程模式） | 最近 Release 是否附带校验和文件（SHA256SUMS 等） |
| `release.binaries_uploaded` | low（仅 GitHub 远程模式） | 是否上传了预编译二进制产物 |
| `release.commit_mapping` | low（仅 GitHub 远程模式） | Release 说明是否把产物对应到某个 commit/tag |

## 危险文件与仓库卫生

| 规则 ID | 默认等级 | 检查内容 |
|---------|----------|----------|
| `security.dangerous_files` | high | 基于文件名探测疑似密钥载体（`.env`、`*.pem`、`*.key`、`id_rsa`…），**误报容忍度极高** |
| `security.secret_assignments` | high | 扫描被跟踪文本文件中的 `NAME=value` 字面密钥（忽略表达式与占位符） |
| `security.large_files` | low | 仓库中的超大文件（默认 5MB，媒体/压缩包 1MB），建议迁移到 Git LFS 或 Release |

---

## 覆盖与扩展

```yaml
# 禁用
disabled_rules: [community.codeowners]

# 改等级
severity_overrides:
  docs.links.dead: high

# 逐规则块
rules:
  security.large_files:
    enabled: false
  repo.readme.limitations:
    severity: info
```

自定义规则（`custom_rules`）支持 `regex` 与 `path` 两种类型，无需改代码即可扩展。
详见 [`../../specguard-rules.example.yml`](../../specguard-rules.example.yml)。
