ARG IMAGE=ubuntu/ubuntu:focal
FROM $IMAGE

RUN apt-get update && \
    apt-get install -y \
    bats \
    curl

COPY "./geneos-xtender*.deb" ./
RUN apt-get update && apt-get install -y ./geneos-xtender*.deb && rm ./geneos-xtender*.deb

COPY ./tests/bats/ ./tests/bats/

ENV BATS_DIR="tests/bats"
ENV BATS_EXT_URL="https://raw.githubusercontent.com/mbland/go-script-bash/master/lib/bats"

RUN curl $BATS_EXT_URL/assertion-test-helpers -o $BATS_DIR/assertion-test-helpers && \
curl $BATS_EXT_URL/assertions -o $BATS_DIR/assertions && \
curl $BATS_EXT_URL/background-process -o $BATS_DIR/background-process && \
curl $BATS_EXT_URL/helper-function -o $BATS_DIR/helper-function && \
curl $BATS_EXT_URL/helpers -o $BATS_DIR/helpers

CMD ["/usr/bin/bats", "--tap", "-p", "tests/bats/post_install.bats"]
