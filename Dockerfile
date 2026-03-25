FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY network_tracker/ ./network_tracker/
COPY config.ini .

RUN mkdir -p data

CMD ["python", "-m", "network_tracker.main"]
