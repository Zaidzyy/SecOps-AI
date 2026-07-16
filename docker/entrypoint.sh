#!/bin/sh
# SecOps-AI container entrypoint: migrate -> (maybe) seed demo data -> serve.
set -e

# 1. Schema up to date before anything touches the DB. Idempotent (see
#    migrations.py); explicit here so a schema problem fails the boot loudly
#    instead of surfacing as a 500 later.
python -c "
import sqlite3, config, migrations
conn = sqlite3.connect(config.DB_PATH)
migrations.migrate(conn, verbose=True)
conn.close()
"

# 2. First-boot demo seed (SECOPS_SEED_DEMO=1): replay the public-IP capture
#    through the real pipeline so the map and feed are populated on first
#    login. Only when the detections table is EMPTY -- re-seeding every boot
#    would duplicate rows in the persistent volume.
#
#    The replay subprocess forces threading mode: it uses the pipeline's real
#    worker threads and is not running under gunicorn's monkey-patched gevent
#    worker, so gevent async mode would be wrong there.
if [ "${SECOPS_SEED_DEMO:-0}" = "1" ] && python -c "
import sqlite3, config, sys
conn = sqlite3.connect(config.DB_PATH)
n = conn.execute('SELECT COUNT(*) FROM detections').fetchone()[0]
conn.close()
sys.exit(0 if n == 0 else 1)
"; then
    echo "[entrypoint] Seeding demo data (samples/demo-public-ips.pcap) ..."
    SECOPS_SOCKETIO_ASYNC_MODE=threading \
        python app_groq.py --replay samples/demo-public-ips.pcap \
        || echo "[entrypoint] WARN: demo seed failed (continuing to serve)"
else
    echo "[entrypoint] Demo seed skipped (disabled or already seeded)."
fi

# 3. Serve. ONE gevent worker: Socket.IO needs sticky sessions, so scaling
#    happens with more instances + a message queue, never more workers. The
#    GeventWebSocketWorker is what makes real WebSocket upgrades work --
#    plain gevent would silently degrade every client to long-polling.
exec gunicorn \
    --worker-class geventwebsocket.gunicorn.workers.GeventWebSocketWorker \
    --workers 1 \
    --bind "${SECOPS_HOST:-0.0.0.0}:${SECOPS_PORT:-5000}" \
    --timeout 120 \
    --access-logfile - \
    app_groq:app
