# Controller image. Build context is vitrag/hierarchy (it needs shared/ as well).
FROM python:3.11-slim
WORKDIR /app
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
COPY controller/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY shared/ /app/
COPY controller/ /app/controller/
CMD ["python", "-m", "uvicorn", "controller.app:app", "--host", "0.0.0.0", "--port", "8100"]
