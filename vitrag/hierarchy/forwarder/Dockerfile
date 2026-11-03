FROM python:3.11-slim
WORKDIR /app
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir requests==2.32.3
COPY shared/ /app/
COPY forwarder/rules.py forwarder/forwarder.py /app/
CMD ["python", "/app/forwarder.py"]
