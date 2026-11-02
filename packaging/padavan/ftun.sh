#!/bin/sh
# Padavan/Entware启停入口；安装后按实际路径配置下面三个变量。
FTUN_BIN=${FTUN_BIN:-/opt/bin/ftun}
FTUN_CONFIG=${FTUN_CONFIG:-/opt/etc/ftun/config.json}
FTUN_PIDFILE=${FTUN_PIDFILE:-/opt/var/run/ftun.pid}

case "$1" in
  start) exec "$FTUN_BIN" run -b -c "$FTUN_CONFIG" -p "$FTUN_PIDFILE" ;;
  stop) exec "$FTUN_BIN" stop -p "$FTUN_PIDFILE" --timeout 15 ;;
  reload) exec "$FTUN_BIN" reload -p "$FTUN_PIDFILE" --timeout 30 ;;
  status) exec "$FTUN_BIN" status -p "$FTUN_PIDFILE" ;;
  *) echo "Usage: $0 {start|stop|reload|status}" >&2; exit 2 ;;
esac
