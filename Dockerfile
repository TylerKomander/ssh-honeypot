FROM python:3.12-slim 

RUN useradd --system --uid 10001 honey

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY honeypot.py .

USER honey

ENV HONEYPOT_HOST=0.0.0.0 \
    HONEYPOT_PORT=2222 \
    HONEYPOT_LOG_DIR=/data \
    HONEYPOT_HOST_KEY=/data/host.key \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

EXPOSE 2222

CMD ["python", "honeypot.py"]

