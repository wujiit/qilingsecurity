#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd)"

# 可直接在这里填默认值；环境变量会优先覆盖这些默认值。
DEFAULT_WORDFENCE_API_KEY=""
DEFAULT_PRIVATE_KEY_PATH=""
DEFAULT_FEED_TYPE="production"
DEFAULT_COMPONENT_TYPES="plugin,theme"
DEFAULT_MAX_ITEMS="5000"
DEFAULT_LABEL="启灵官方规则包"
DEFAULT_OUTPUT_FILE="$SCRIPT_DIR/package-signed.json"
DEFAULT_BASE_TEMPLATE="$SCRIPT_DIR/package-template.json"

NODE_BIN="${NODE_BIN:-node}"
API_KEY="${WORDFENCE_API_KEY:-$DEFAULT_WORDFENCE_API_KEY}"
PRIVATE_KEY_PATH="${QILING_RULES_PRIVATE_KEY:-$DEFAULT_PRIVATE_KEY_PATH}"
FEED_TYPE="${QILING_WORDFENCE_FEED_TYPE:-$DEFAULT_FEED_TYPE}"
COMPONENT_TYPES="${QILING_COMPONENT_TYPES:-$DEFAULT_COMPONENT_TYPES}"
MAX_ITEMS="${QILING_RULES_MAX_ITEMS:-$DEFAULT_MAX_ITEMS}"
PACKAGE_LABEL="${QILING_RULES_LABEL:-$DEFAULT_LABEL}"
OUTPUT_FILE="${QILING_RULES_OUTPUT:-$DEFAULT_OUTPUT_FILE}"
BASE_TEMPLATE="${QILING_RULES_BASE_TEMPLATE:-$DEFAULT_BASE_TEMPLATE}"
PACKAGE_VERSION="${QILING_RULES_VERSION:-$(date -u +%Y.%m.%d)-wf}"

print_error() {
  echo ""
  echo "[错误] $1"
  echo ""
}

if ! command -v "$NODE_BIN" >/dev/null 2>&1; then
  print_error "未找到 node 命令，请先安装 Node.js，或通过 NODE_BIN 指定可执行文件。"
  exit 1
fi

if [[ -z "$API_KEY" ]]; then
  print_error "未配置 Wordfence API key。请编辑脚本顶部 DEFAULT_WORDFENCE_API_KEY，或先执行：
export WORDFENCE_API_KEY='你的API密钥'"
  exit 1
fi

if [[ -z "$PRIVATE_KEY_PATH" ]]; then
  print_error "未配置官方私钥路径。请编辑脚本顶部 DEFAULT_PRIVATE_KEY_PATH，或先执行：
export QILING_RULES_PRIVATE_KEY='/你的私钥路径/qiling-official-private.pem'"
  exit 1
fi

if [[ ! -f "$PRIVATE_KEY_PATH" ]]; then
  print_error "找不到私钥文件：$PRIVATE_KEY_PATH"
  exit 1
fi

if [[ ! -f "$BASE_TEMPLATE" ]]; then
  print_error "找不到基础模板文件：$BASE_TEMPLATE"
  exit 1
fi

mkdir -p "$(dirname -- "$OUTPUT_FILE")"

echo "============================================================"
echo "启灵官方规则包一键生成"
echo "============================================================"
echo "Feed 类型:      $FEED_TYPE"
echo "组件范围:      $COMPONENT_TYPES"
echo "规则包版本:    $PACKAGE_VERSION"
echo "输出文件:      $OUTPUT_FILE"
echo "基础模板:      $BASE_TEMPLATE"
echo ""

"$NODE_BIN" "$SCRIPT_DIR/build-wordfence-package.mjs" \
  --api-key "$API_KEY" \
  --private-key "$PRIVATE_KEY_PATH" \
  --feed-type "$FEED_TYPE" \
  --component-types "$COMPONENT_TYPES" \
  --max-items "$MAX_ITEMS" \
  --version "$PACKAGE_VERSION" \
  --label "$PACKAGE_LABEL" \
  --base-template "$BASE_TEMPLATE" \
  --out "$OUTPUT_FILE" \
  "$@"

echo ""
echo "生成完成：$OUTPUT_FILE"
echo "下一步：把这个 package-signed.json 发给用户，在插件后台“官方扫描规则更新”里导入即可。"
