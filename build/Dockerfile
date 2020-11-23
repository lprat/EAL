FROM debian:buster

LABEL maintainer="Lionel"
LABEL version="1.0"

RUN echo "deb http://security.debian.org/ buster/updates main" >> /etc/apt/sources.list

RUN apt-get update \
    && apt-get -y --no-install-recommends install \
        git \
        gcc-multilib \
        build-essential \
        autoconf \
        automake \
        libtool \
        patch \
        golang \
        git-core \
        python3-dev \
        ca-certificates \
        unzip \
        zip \
        sed \
        openssl \
        wget \
        curl \
        python3-pip \
        python3-setuptools \
        pkg-config \
        gcc-mingw-w64 \
        libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install yara-python plyara
COPY ./merge_yararules.py /opt
COPY ./make_eal.sh /
COPY ./yara.patch /opt
RUN chmod +x /make_eal.sh && chmod +x /opt/merge_yararules.py
ENTRYPOINT ["/bin/bash", "/make_eal.sh", "\"@$\""]
