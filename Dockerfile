FROM python:3.11-slim

WORKDIR /app

RUN pip install uv

COPY pyproject.toml .
COPY src/ src/

RUN uv pip install --system .

ENV PORT=3000
EXPOSE 3000

CMD ["lnurl-hydra-login"]
