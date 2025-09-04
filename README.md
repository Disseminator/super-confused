# super-confused

一款下一代依赖混淆分析工具，用于识别源代码和SBOM文件中可能存在的依赖混淆机会。
super-confused 支持多种包清单和SBOM文件格式，可在本地或远程运行。

## 功能

- **支持17种文件格式**：package.json、requirements.txt、pyproject.toml、go.mod、Cargo.toml、composer.json、Gemfile、pom.xml、build.gradle、yarn.lock、package-lock.json、bom.json、sbom.json、bom.xml、sbom.xml、go.sum
- **远程扫描**：直接扫描 GitHub/GitLab URL 中的文件
- **SBOM支持**：支持 CycloneDX 和 SPDX 格式（JSON/XML）
- **实时验证**：检查包在公共注册表中的存在性
- **JSON输出**：提供机器可读的结果，方便集成到 CI/CD 流程

## 安装

### NPM 包

```bash
npm install super-confused
```

### 源码安装
```shell
git clone https://github.com/6mile/super-confused.git
cd super-confused
chmod +x super-confused.js
```

## 使用方法
```text
# 扫描本地文件
./super-confused.js package.json

# 扫描目录
./super-confused.js .

# 扫描远程文件
./super-confused.js https://github.com/user/repo/blob/main/package.json

# JSON 输出
./super-confused.js --json package.json
```

## 支持的生态系统
- npm (Node.js)
- PyPI (Python)
- Cargo (Rust)
- Packagist (PHP)
- RubyGems (Ruby)
- Maven (Java)
- Go modules