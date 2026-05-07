FROM python:3.12-slim-bookworm

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    BITSENTRY_DOCKER=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

COPY . .

RUN useradd --create-home --uid 1000 --shell /bin/bash bitsentry \
    && chown -R bitsentry:bitsentry /app

USER bitsentry

ENTRYPOINT ["python", "bitsentry.py"]
CMD ["--help"]
