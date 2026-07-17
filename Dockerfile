# SecOps-AI console image (Phase 4b).
#
# Deliberately unprivileged: the container does REPLAY-ONLY capture (the demo
# seed pcap at first boot). Live NIC sniffing is a host/bare-metal feature --
# it would need --privileged or host networking, which this image refuses to
# assume. Runs as a non-root user on a real WSGI server (gunicorn + gevent
# worker), never the Werkzeug dev server.
#
# 3.13-slim matches the Python the repo is developed and the model pickles are
# serialized under. Runtime requirements only -- no TensorFlow; the shipped
# detector is the sklearn GBT (see requirements.txt for the rationale).
FROM python:3.13-slim

WORKDIR /app

# Dependency layer first so code edits don't re-install anything.
COPY requirements.txt requirements-deploy.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-deploy.txt

# Runtime code + assets, explicitly listed: nothing training-related, no
# tests, no dev database. models/ is <1 MB (GBT + scaler + metadata).
COPY alerts.py app_groq.py attack_mapping.py auth.py cnn_engine.py config.py \
     enrichment.py flow_tracker.py migrations.py ollama_lib.py pipeline.py \
     rag.py reports.py storage.py triage.py ./
COPY models/ models/
COPY static/ static/
COPY templates/ templates/
COPY samples/demo-public-ips.pcap samples/demo-public-ips.pcap
COPY docker/entrypoint.sh /entrypoint.sh

# Non-root from here on. /data holds the SQLite database (declared a volume in
# docker-compose so detections survive container recreation).
RUN useradd --create-home --uid 10001 secops \
    && mkdir -p /data \
    && chown secops:secops /data \
    && chmod +x /entrypoint.sh
USER secops

ENV SECOPS_DB=/data/system_metrics.db \
    SECOPS_HOST=0.0.0.0 \
    SECOPS_PORT=5000 \
    SECOPS_SOCKETIO_ASYNC_MODE=gevent \
    PYTHONUNBUFFERED=1

EXPOSE 5000

# The login page answering is the cheapest "app is actually serving" probe
# that needs no session. stdlib only -- slim has no curl.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/login', timeout=4)" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
