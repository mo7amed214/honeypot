FROM python:3.13-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir asyncua requests urllib3

COPY proxy.py .

EXPOSE 4841

CMD ["python", "proxy.py"]
