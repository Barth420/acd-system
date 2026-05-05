FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.0

COPY app.py /app/

RUN mkdir -p /var/log/product

EXPOSE 5001
CMD ["python", "/app/app.py"]
