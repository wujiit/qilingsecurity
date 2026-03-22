# 启灵安全规则包（官方签名）

> 本目录仅供启灵官方或内部运维/开发发布规则包使用。  
> 终端用户无需进入 `rules/` 目录，也无需执行这里的脚本；用户只需要在插件后台导入你们发出的 `package-signed.json`。

插件已启用“仅官方签名规则包”策略：  
未签名包、第三方签名包会被拒绝导入。

## 1. 规则包模板

编辑模板文件：

- `package-template.json`

必须保留这些字段：

- `package_id`（固定为 `qilingsecurity-rules`）
- `version`
- `rules`
- `rules_sha256`
- `signer`
- `rules_signature`

## 2. 签名前准备（发布端）

仅官方发布端持有私钥，不要放到插件目录或仓库。

生成密钥（示例）：

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out qiling-official-private.pem
openssl rsa -pubout -in qiling-official-private.pem -out qiling-official-public.pem
```

把 `qiling-official-public.pem` 的内容写入插件代码中的官方公钥常量：

- `includes/class-qs-rules.php`

## 3. 生成已签名规则包

### 3.0 一键生成脚本

如果你希望内部直接一条命令出包，可以使用：

```bash
./build-official-rules.command
```

使用前只需要准备两项：

- `Wordfence API key`
- 官方私钥文件路径

你可以直接编辑脚本顶部这两个默认值：

- `DEFAULT_WORDFENCE_API_KEY`
- `DEFAULT_PRIVATE_KEY_PATH`

也可以先临时导出环境变量再执行：

```bash
export WORDFENCE_API_KEY="你的_Wordfence_API_Key"
export QILING_RULES_PRIVATE_KEY="/你的私钥路径/qiling-official-private.pem"
./build-official-rules.command
```

脚本默认会：

- 拉取 `production` feed
- 合并 `package-template.json` 基础扫描规则
- 生成版本号类似 `2026.03.13-wf`
- 输出到当前目录下的 `package-signed.json`

### 3.1 直接从 Wordfence 生成总规则包

如果你们内部已经有 Wordfence API key，可以直接用：

```bash
node build-wordfence-package.mjs \
  --api-key "$WORDFENCE_API_KEY" \
  --private-key /secure/path/qiling-official-private.pem \
  --out wordfence-package-signed.json
```

也支持先把 Wordfence 响应保存到本地，再离线转换：

```bash
node build-wordfence-package.mjs \
  --feed-file ./wordfence-production.json \
  --private-key /secure/path/qiling-official-private.pem \
  --out wordfence-package-signed.json
```

脚本默认会读取 `production` feed，并把 `package-template.json` 里的现有扫描规则一起合并，最终输出“扫描规则 + 漏洞情报”的总包。  
常用参数：

- `--feed-type production|scanner`
- `--base-template ./package-template.json`
- `--component-types plugin,theme`
- `--max-items 5000`
- `--min-plugin-version 1.16.0`
- `--version 2026.03.13-wf`
- `--label "Qiling Security Wordfence Feed"`

### 3.2 使用现有签名脚本

如果你是先手工整理 `package-template.json`，再签名，也可以继续使用现有签名脚本：

```bash
php sign-package.php \
  --in package-template.json \
  --out package-signed.json \
  --private-key /secure/path/qiling-official-private.pem \
  --signer qiling-official-v1
```

脚本会自动：

- 计算 `rules_sha256`
- 生成 `rules_signature`
- 输出可直接上传的 `package-signed.json`

`rules.component_vulnerability_feed` 可用于承载插件/主题漏洞情报。  
推荐字段：

- `component_type`: `plugin` 或 `theme`
- `slug`: 组件 slug
- `title`: 漏洞标题
- `severity`: `critical` / `warning` / `info`
- `affected_versions`: 受影响版本表达式，例如 `>=5.0,<5.9.4`
- `fixed_in`: 修复版本
- `reference`: 参考链接
- `source`: 情报来源，例如 `wordfence`
- `cve`: 可选漏洞编号

## 4. 用户侧使用

用户在插件后台上传 `package-signed.json` 即可。  
插件会自动验证：

- 哈希是否匹配
- 签名是否来自官方公钥

验证失败则拒绝导入。

用户不需要：

- 编辑 `package-template.json`
- 运行 `sign-package.php`
- 运行 `build-wordfence-package.mjs`
- 了解 `rules/` 目录内部结构
