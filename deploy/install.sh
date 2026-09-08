#!/usr/bin/env bash
# Agent2 服务器部署脚本（Ubuntu 20.04+/Debian 11+/CentOS 7+）
# 用法:  sudo bash install.sh
set -euo pipefail

APP_NAME="agent2"
APP_DIR="/opt/${APP_NAME}"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
ENV_FILE="/etc/agent2/env"
RUN_USER="agent2"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(dirname "${SCRIPT_DIR}")"     # deploy/ 的上一级 = agent2 根

echo "==> Agent2 安装程序"
echo "    源目录 : ${SRC_DIR}"
echo "    安装到 : ${APP_DIR}"

# 0. 前置检查
command -v python3 >/dev/null || { echo "错误: 未找到 python3"; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,10), "需要 Python 3.10+"' \
  || { echo "错误: 需要 Python 3.10+（当前 $(python3 --version)）"; exit 1; }

# 1. 创建专用用户
if ! id -u "${RUN_USER}" >/dev/null 2>&1; then
  useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${RUN_USER}"
  echo "    已创建系统用户 ${RUN_USER}"
fi

# 2. 拷贝代码（排除本地数据/临时文件）
install -d -o "${RUN_USER}" -g "${RUN_USER}" "${APP_DIR}"
rsync -a --delete \
      --exclude data --exclude .tmp_doc --exclude __pycache__ \
      --exclude '*.pyc' --exclude .git --exclude tests --exclude lab \
      "${SRC_DIR}/" "${APP_DIR}/" 2>/dev/null \
  || cp -r "${SRC_DIR}"/main.py "${SRC_DIR}"/asset_agent "${SRC_DIR}"/webui \
         "${SRC_DIR}"/scope.example.json "${SRC_DIR}"/jobs.example.json \
         "${SRC_DIR}"/README.md "${SRC_DIR}"/DELIVERY_CHECKLIST.md "${APP_DIR}/"
install -d -o "${RUN_USER}" -g "${RUN_USER}" \
        "${APP_DIR}/data/reports" "${APP_DIR}/data/exports" "${APP_DIR}/data/logs"

# 3. 授权范围（若不存在则从示例创建）
if [ ! -f "${APP_DIR}/data/scope.json" ]; then
  cp "${APP_DIR}/scope.example.json" "${APP_DIR}/data/scope.json"
  echo "    [重要] 已生成 data/scope.json 示例，请把 example.com 替换为你的授权资产！"
fi
# 定时任务清单（若不存在则从示例创建，默认全部停用）
if [ ! -f "${APP_DIR}/data/jobs.json" ]; then
  cp "${APP_DIR}/jobs.example.json" "${APP_DIR}/data/jobs.json"
  echo "    [重要] 已生成 data/jobs.json 示例，请按需启用任务"
fi

# 4. 环境变量（生成随机 Token）
install -d -m 700 /etc/agent2
if [ ! -f "${ENV_FILE}" ]; then
  TOKEN="$(openssl rand -hex 16 2>/dev/null || head -c 32 /dev/urandom | base64)"
  cat > "${ENV_FILE}" <<EOF
# Agent2 环境变量（sudo cat ${ENV_FILE} 查看）
AGENT2_TOKEN=${TOKEN}
AGENT2_VULN_DB=
AGENT2_LOG_LEVEL=info
EOF
  chmod 600 "${ENV_FILE}"
  echo "    已生成访问 Token（见 ${ENV_FILE}）"
fi

# 5. 安装 systemd 服务
cp "${SCRIPT_DIR}/agent2.service" "${SERVICE_FILE}"
chown -R "${RUN_USER}:${RUN_USER}" "${APP_DIR}"
systemctl daemon-reload
systemctl enable --now "${APP_NAME}"
systemctl --no-pager status "${APP_NAME}" --lines=5 || true

echo
echo "==> 安装完成"
echo "    服务: systemctl status ${APP_NAME} / journalctl -u ${APP_NAME} -f"
echo "    仪表盘: http://<服务器IP>:8000  （Bearer Token 见 ${ENV_FILE}）"
echo "    下一步: 编辑 ${APP_DIR}/data/scope.json 填入授权资产，然后 systemctl restart ${APP_NAME}"
