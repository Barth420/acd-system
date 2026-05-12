FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.0.0

COPY app.py /app/

# Logs directory — Wazuh agent will tail this
RUN mkdir -p /var/log/auth

EXPOSE 5000
CMD ["python", "/app/app.py"]
