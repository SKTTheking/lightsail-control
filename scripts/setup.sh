#!/usr/bin/env bash
# Control-center host: Ubuntu 24.04 LTS. Does not change SSH or firewall rules.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "$(id -u)" -ne 0 ]; then echo '请使用 sudo bash scripts/setup.sh 域名'; exit 1; fi
domain=${1:-}
if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$ ]] || [[ "$domain" != *.* ]] || [[ "$domain" == *..* ]]; then
  echo '请填写已指向这台服务器的域名，例如：sudo bash scripts/setup.sh panel.example.com'; exit 1
fi
if ! command -v docker >/dev/null || ! docker compose version >/dev/null 2>&1; then
  . /etc/os-release
  if [[ "$ID" != ubuntu || "$VERSION_ID" != 24.04 ]]; then
    echo '自动安装 Docker 仅支持 Ubuntu 24.04；其他系统请先安装 Docker Engine 和 Compose v2。'; exit 1
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get -o DPkg::Lock::Timeout=180 update
  apt-get -o DPkg::Lock::Timeout=180 install -y docker.io docker-compose-v2 ca-certificates
fi
systemctl enable --now docker
umask 077
mkdir -p data/control data/secrets data/caddy data/caddy-config
chown 10001:10001 data/control
if [ ! -f data/secrets/admin_password ]; then
  od -An -N24 -tx1 /dev/urandom | tr -d ' \n' > data/secrets/admin_password
  chown 10001:10001 data/secrets/admin_password
  chmod 400 data/secrets/admin_password
fi
printf 'LC_DOMAIN=%s\n' "$domain" > .env
docker compose up -d --build
echo "控制中心正在启动：https://$domain"
echo '首次账号：admin'
echo '首次密码保存在 data/secrets/admin_password。用 sudo cat data/secrets/admin_password 查看。'
echo '请在光帆放行 TCP 80/443；若系统防火墙已启用，也需放行这两个端口。'
echo '查看启动情况：sudo docker compose logs --tail=60 control caddy'
