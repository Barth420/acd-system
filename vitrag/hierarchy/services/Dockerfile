# One small image holds all five Flask services; compose picks the module with `command`.
FROM python:3.11-slim
WORKDIR /app
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir flask==3.0.3 requests==2.32.3 psycopg2-binary==2.9.9 redis==5.0.8
COPY shared/ /app/
COPY services/svc /app/svc
