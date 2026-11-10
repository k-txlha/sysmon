FROM python:3.11-slim

# Build from the repository root: docker build -f worker/Dockerfile .
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY worker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY worker /app/worker

CMD ["python", "-m", "worker.main"]
