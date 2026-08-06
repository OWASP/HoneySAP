# HoneySAP Dockerfile

FROM ubuntu:22.04

LABEL maintainer="martin.gallo@gmail.com"

# Install system packages
RUN apt-get update && apt-get install -y \
        git \
        python3-pip \
        python3-dev \
        build-essential \
        python3-yaml && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY . /opt/honeysap
WORKDIR /opt/honeysap

# Install pysap: use a local wheel/tarball if one was bundled with the
# source tree (offline / air-gapped builds), otherwise pull from GitHub.
RUN if find pysap/dist -name "pysap-*.tar.gz" 2>/dev/null | grep -q .; then \
        python3 -m pip install "$(find pysap/dist -name 'pysap-*.tar.gz' | sort | tail -1)"; \
    else \
        python3 -m pip install "git+https://github.com/OWASP/pysap.git"; \
    fi

# Install HoneySAP
RUN python3 -m pip install . && \
    rm -rf /tmp/* /var/tmp/*

# SAP Router     : 3299
# SAP Dispatcher : 3200
# SAP Gateway    : 3300
# SAP ICM (HTTP) : 8000
# SAP Msg Server : 3600
# SAP MS (HTTP)  : 8100
EXPOSE 3299 3200 3300 8000 3600 8100

CMD ["/usr/local/bin/honeysap", "--config-file", "profiles/internal.yml"]
