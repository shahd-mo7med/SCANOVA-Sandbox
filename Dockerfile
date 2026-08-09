FROM debian:bookworm

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:99

RUN apt-get update && apt-get install -y \
    chromium \
    xvfb \
    x11vnc \
    x11-utils \
    novnc \
    websockify \
    python3 \
    python3-pip \
    python3-venv \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash scanova

WORKDIR /app

COPY requirements.txt .

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY static ./static

RUN chown -R scanova:scanova /app

USER scanova

EXPOSE 8000 5900 6080

CMD ["bash", "-c", "\
Xvfb :99 -screen 0 1280x720x24 -ac & \
x11vnc -display :99 -forever -shared -rfbport 5900 -nopw & \
websockify --web=/usr/share/novnc 6080 localhost:5900 & \
exec /opt/venv/bin/uvicorn server:app --host 0.0.0.0 --port ${PORT:-8000} \
"]