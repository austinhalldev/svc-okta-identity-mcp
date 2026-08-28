FROM python:3.12-slim

RUN useradd --create-home --shell /usr/sbin/nologin appuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY auth.py config.py dpop.py identity_fields.py okta_users.py server.py token_cache.py ./

ENV MCP_HOST=0.0.0.0
EXPOSE 8000

USER appuser

CMD ["python", "server.py"]
