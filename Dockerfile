# Build Command Example:
# $ docker build -t pydhcp .

FROM python:3

ENV PYTHONUNBUFFERED 1
RUN pip install --no-cache --upgrade pip

WORKDIR /tmp/dhcp
COPY . .
RUN pip install ./pynetbox*.tar.gz
RUN pip install .["netbox"] && \
    rm -rf /tmp/dhcp

WORKDIR /
ENTRYPOINT ["/usr/local/bin/pydhcp"]
