FROM alpine:latest

LABEL MAINTAINER="jiangyuchao"
LABEL description="Nmap Patrowl Engine"
LABEL Version="1.0.0"

ENV LOGLEVEL debug

# Set the working directory
RUN mkdir -p /opt/patrowl-engines/nessus \
    && mkdir -p /opt/patrowl-engines/nessus/logs \
    && mkdir -p /opt/patrowl-engines/nessus/results \
    && mkdir -p /opt/patrowl-engines/nessus/reports \
    && mkdir -p /opt/patrowl-engines/nessus/external-libs
WORKDIR /opt/patrowl-engines/nessus

# Copy the current directory contents into the container at /
COPY __init__.py engine-nessus.py parser.py requirements.txt README.md VERSION nessus.json ./
COPY etc/ ./etc/
COPY external-libs/ ./external-libs/

RUN apk add --update \
    python3 python3-dev py3-pip \
    git \
  && rm -rf /var/cache/apk/*
RUN pip3 install --upgrade pip
RUN pip3 install --trusted-host pypi.python.org -r requirements.txt

WORKDIR /opt/patrowl-engines/nessus/external-libs/nessrest/
RUN pip3 install --trusted-host pypi.python.org -e /opt/patrowl-engines/nessus/external-libs/nessrest/
WORKDIR /opt/patrowl-engines/nessus/

# TCP port exposed by the container (NAT)
EXPOSE 5001

# Run app.py when the container launches
CMD ["gunicorn", "engine-nessus:app", "-b", "0.0.0.0:5001", "--preload", "--timeout", "300", "--access-logfile", "-", "--log-file", "/opt/patrowl-engines/nessus/logs/patrowlengine.nessus.log", "--log-level", "$LOGLEVEL", "--capture-output"]
