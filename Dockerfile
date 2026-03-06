FROM python:3.11-slim

WORKDIR /app

RUN pip install uv

COPY pyproject.toml .
RUN uv pip install --system .

COPY src/ src/

ENV PORT=3000
EXPOSE 3000

CMD ["lnurl-hydra-login"]
