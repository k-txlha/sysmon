FROM python:3.11-slim

# Build from the repository root: docker build -f backend/Dockerfile .
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies if required
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the backend package and shared detection rule metadata.
COPY backend /app/backend
COPY worker/detection/rules /app/worker/detection/rules

EXPOSE 8000

CMD ["python", "-m", "backend"]
