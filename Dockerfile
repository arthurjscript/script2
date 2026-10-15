# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build

WORKDIR /src
COPY pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir --prefix=/install .


FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HEARTBEAT_FILE=/tmp/heartbeat

COPY --from=build /install /usr/local

RUN useradd --create-home --uid 10001 app
USER app

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import os,sys,time; sys.exit(time.time() - os.path.getmtime(os.environ['HEARTBEAT_FILE']) > 60)"

ENTRYPOINT ["python", "-m", "script2"]
