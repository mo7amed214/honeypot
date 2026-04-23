FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/workspace

WORKDIR /workspace

COPY ml/lstm_session/requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.5.1
RUN pip install --no-cache-dir -r /tmp/requirements.txt

CMD ["python", "-m", "ml.lstm_session.train", "--scenario-root", "artifacts/scenario-runs", "--output-dir", "ml/runs/latest"]
