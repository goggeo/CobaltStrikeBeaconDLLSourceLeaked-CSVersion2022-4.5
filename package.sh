#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# package.sh  ——  将 Windows 的 package.bat 逻辑转换为可在 Bash 下运行的脚本
# 用途：批量调用 MSBuild 构建 beacon / dnsb / extc2 / pivot 四个项目，
#       覆盖 win32 与 x64 两个平台，并支持不同 RefLoader 大小（5K、100K）。
# 兼容：Git Bash / WSL / Cygwin / MSYS2 / macOS（前提：能调用到 msbuild）
# 注意：项目本身为 Windows 工程（.vcxproj），真正的编译须在 Windows 工具链下完成。
# -----------------------------------------------------------------------------
set -euo pipefail

# ========== 实用函数 ==========
log() { echo -e "\033[1;36m[+] $*\033[0m"; }
err() { echo -e "\033[1;31m[-] $*\033[0m" >&2; }
die() { err "$*"; exit 1; }

# ========== 定位 MSBuild ==========
# 优先使用 PATH 中的 msbuild；否则尝试通过 vswhere 定位；
# 若仍不可用，尝试使用 dotnet msbuild（.NET SDK 以内置）。
find_msbuild() {
  if command -v msbuild >/dev/null 2>&1; then
    echo "msbuild"
    return 0
  fi
  # Windows 上常见 vswhere 位置（Git Bash/WSL 可访问）
  local VSWHERE_1="/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
  local VSWHERE_2="/mnt/c/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe"
  local VSWHERE=""
  if [ -x "$VSWHERE_1" ]; then VSWHERE="$VSWHERE_1"; fi
  if [ -z "$VSWHERE" ] && [ -x "$VSWHERE_2" ]; then VSWHERE="$VSWHERE_2"; fi
  if [ -n "$VSWHERE" ]; then
    local MSBUILD_PATH
    MSBUILD_PATH="$($(printf '"%s"' "$VSWHERE") -latest -requires Microsoft.Component.MSBuild -find MSBuild/**/Bin/MSBuild.exe 2>/dev/null | head -n 1)"
    if [ -n "$MSBUILD_PATH" ] && [ -f "$MSBUILD_PATH" ]; then
      echo "$MSBUILD_PATH"
      return 0
    fi
  fi
  if command -v dotnet >/dev/null 2>&1; then
    echo "dotnet msbuild"
    return 0
  fi
  return 1
}

MSBUILD_CMD="$(find_msbuild || true)"
[ -z "$MSBUILD_CMD" ] && die "未找到 MSBuild。请在 Windows 开发环境中运行，或将 msbuild 加入 PATH。"
log "使用 MSBuild: $MSBUILD_CMD"

# ========== 目录准备（与 BAT 保持一致） ==========
# 解决某些大小写敏感文件系统下的 PDB 目录问题
rm -rf release x64/release || true
mkdir -p release x64/release

# ========== 通用构建函数 ==========
# 参数使用环境变量：
#   projects   —— 要构建的项目名数组（不含后缀）
#   platforms  —— 平台列表：win32 / x64
#   CSRefLoadSize —— 传给 MSBuild 的 /p:RefLoadSize=xx
#   UDRLExtension / CSOptimized —— 仅用于日志展示；（如需可扩展为 /p:Optimization）
build_em() {
  log "BuildEm Projects: (${projects[*]})  Platforms: (${platforms[*]})"
  for p in "${projects[@]}"; do
    for t in "${platforms[@]}"; do
      echo "======================================================================="
      echo "Building Project: $p  Platform: $t  UDRLExtension: ${UDRLExtension:-}  CSRefLoadSize: ${CSRefLoadSize:-}  CSOptimized: ${CSOptimized:-}"
      echo "======================================================================="
      set +e
      $MSBUILD_CMD "$p.vcxproj" /t:Build /p:Configuration=Release /p:Platform="$t" ${CSRefLoadSize:-}
      local status=$?
      set -e
      echo "Build Status: $status"
      if [ $status -ne 0 ]; then die "msbuild 失败：$p ($t)"; fi
      echo "---------- msbuild Successful ----------"
    done
  done
}

# ========== 第一轮：标准 5K Ref Loader ==========
log "Building Standard (5K Ref loader) Beacons..."
CSRefLoadSize="/p:RefLoadSize=5"
UDRLExtension=""
CSOptimized="MinSpace"
projects=(beacon dnsb extc2 pivot)
platforms=(win32 x64)
build_em

# ========== 第二轮：更大 Ref Loader（UDRL） ==========
log "Building Beacons with Larger Ref Loader Size (UDRL)..."
# 如需 50k / 1000k 可按需解注释并设置 UDRLExtension
# CSRefLoadSize="/p:RefLoadSize=50";  UDRLExtension=".rl50k"
CSRefLoadSize="/p:RefLoadSize=100"; UDRLExtension=".rl100k"
# CSRefLoadSize="/p:RefLoadSize=1000"; UDRLExtension=".rl1000k"

projects=(beacon dnsb extc2 pivot)
platforms=(win32)
CSOptimized="MinSpace"
build_em

platforms=(x64)
CSOptimized="Disabled"   # 与 BAT 相同：x64 大 Ref 时禁优化以缩短编译时间
build_em

log "全部构建完成。"
