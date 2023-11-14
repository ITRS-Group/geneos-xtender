ARG IMAGE="ubuntu:focal"
FROM $IMAGE

ARG IMAGE
ENV IMAGE=$IMAGE

# If IMAGE=ubuntu:focal, then use apt-get to install bats and curl.
# If IMAGE=oraclelinux:8, then use yum to install bats and curl.
RUN if [ "$IMAGE" = "ubuntu:focal" ]; then \
    apt-get update && \
    apt-get install -y \
    bats \
    curl; \
    elif [ "$IMAGE" = "oraclelinux:8" ]; then \
    dnf install -y oracle-epel-release-el8 && \
    dnf config-manager --enable ol8_developer_EPEL && \
    dnf install -y \
    bats \
    curl; \
    fi

# If IMAGE=ubuntu:focal, then use apt-get to install the geneos-xtender deb
# package. If IMAGE=oraclelinux:8, then use yum to install the geneos-xtender
# rpm package.
COPY "./geneos-xtender*.deb" ./
COPY "./geneos-xtender*.rpm" ./

RUN if [ "$IMAGE" = "ubuntu:focal" ]; then \
    apt-get update && \
    apt-get install -y ./geneos-xtender*.deb && \
    rm ./geneos-xtender*.deb; \
    rm ./geneos-xtender*.rpm; \
    elif [ "$IMAGE" = "oraclelinux:8" ]; then \
    dnf install -y ./geneos-xtender*.rpm && \
    rm ./geneos-xtender*.deb; \
    rm ./geneos-xtender*.rpm; \
    fi

COPY ./tests/bats/ ./tests/bats/

ENV BATS_DIR="tests/bats"
ENV BATS_EXT_URL="https://raw.githubusercontent.com/mbland/go-script-bash/master/lib/bats"

RUN curl $BATS_EXT_URL/assertion-test-helpers -o $BATS_DIR/assertion-test-helpers && \
curl $BATS_EXT_URL/assertions -o $BATS_DIR/assertions && \
curl $BATS_EXT_URL/background-process -o $BATS_DIR/background-process && \
curl $BATS_EXT_URL/helper-function -o $BATS_DIR/helper-function && \
curl $BATS_EXT_URL/helpers -o $BATS_DIR/helpers

CMD ["/usr/bin/bats", "--tap", "tests/bats/post_install.bats"]
