FROM python:3.14.3-slim

WORKDIR /app
COPY prob.py ./

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'python prob.py',stderr"]
