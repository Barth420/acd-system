FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir fastapi==0.115.0 uvicorn==0.30.6
COPY tools/alert_sink.py /app/
CMD ["python", "-m", "uvicorn", "alert_sink:app", "--host", "0.0.0.0", "--port", "8099"]
