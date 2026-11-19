# hmi/Dockerfile.app - image for hmi_ingest and the dashboard
# Debian bookworm = the same Python 3.11 + Tkinter as Raspberry Pi OS on the host.
FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        python3 python3-tk python3-pymysql fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app
COPY common/ common/
COPY hmi/hmi_ingest.py hmi/nas_logger.py hmi/dashboard.py hmi/
# The command (ingest or dashboard) is chosen in docker-compose.yml
