# HoneySAP Dockerfile for running HoneySAP

FROM ubuntu:14.04

MANTAINER mgallo@secureauth.com

# Install system packages
RUN apt-get update && apt-get install -y \
        git \
        python-pip \
        python-dev \
        build-essential && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

# Install extra python packages
RUN pip install "git+https://github.com/rep/hpfeeds.git#egg=hpfeeds"

WORKDIR /opt/honeysap
VOLUME /opt/honeysap

# Clone git repo and install HoneySAP
RUN cd /opt/honeysap && \
    python setup.py install && \
    rm -rf /tmp/* /var/tmp/*

EXPOSE 3299 8001

CMD ["/usr/local/bin/honeysap", "--config-file", "honeysap.yml"]
