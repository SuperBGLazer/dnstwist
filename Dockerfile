FROM python:3.11-slim

WORKDIR /opt/dnstwist

ARG phash

RUN apt-get update && \
    export DEBIAN_FRONTEND=noninteractive && \
    apt-get install -y --no-install-recommends ca-certificates build-essential && \
    if [ -n "$phash" ]; then apt-get install -y --no-install-recommends chromium-driver; fi && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

COPY . /opt/dnstwist/

RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt

ENTRYPOINT ["./webapp/dnstwist.py"]