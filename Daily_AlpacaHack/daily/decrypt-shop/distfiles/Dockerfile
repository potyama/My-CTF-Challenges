FROM python:3.14.3-slim

WORKDIR /app
COPY prob.py /app/prob.py

RUN apt-get update \
    && apt-get install -y --no-install-recommends socat \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pycryptodome

CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:'python prob.py',stderr"]
