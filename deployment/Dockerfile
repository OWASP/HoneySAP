# HoneySAP Dockerfile for running HoneySAP

FROM ubuntu:18.04

MAINTAINER mgallo@secureauth.com

# Install system packages
RUN apt-get update && apt-get install -y \
        git \
        python-pip \
        python-dev \
        build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY . /opt/honeysap
WORKDIR /opt/honeysap

# Clone git repo and install HoneySAP
RUN cd /opt/honeysap && \
    python setup.py install && \
    rm -rf /tmp/* /var/tmp/*

# Install extra python packages
RUN pip install -r requirements-optional.txt

EXPOSE 3299 8001

CMD ["/usr/local/bin/honeysap", "--config-file", "honeysap.yml"]
