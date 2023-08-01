ARG IMAGE=ubuntu/ubuntu:latest
FROM --platform=linux/amd64 $IMAGE

# PKG can be deb OR rpm
ARG PKG="deb"
RUN if [ "$PKG" = "deb" ] ; then \
      apt-get update && \
      apt-get install -y \
      bats \
      curl \
  ; elif [ "$PKG" = "rpm" ] ; then \
      if $(grep -q 'Oracle.*8' /etc/system-release) ; then \
        dnf install -y oracle-epel-release-el8 dnf-plugins-core && \
        dnf config-manager -y --set-enabled ol8_developer_EPEL* && \
        dnf config-manager -y --set-enabled ol8_codeready_builder && \
        dnf update -y && \
        dnf install -y bats \
    ; elif $(grep -q 'Oracle.*9' /etc/system-release) ; then \
        dnf install -y oracle-epel-release-el9 dnf-plugins-core && \
        dnf config-manager -y --set-enabled ol9_developer_EPEL* && \
        dnf config-manager -y --set-enabled ol9_codeready_builder && \
        dnf update -y && \
        dnf install -y bats \
    ; elif $(grep -q 'Alma.*9' /etc/system-release) ; then \
        dnf install -y epel-release dnf-plugins-core && \
        dnf config-manager -y --set-enabled crb && \
        dnf install -y bats \
    ; else \
        dnf install -y epel-release && \
        /usr/bin/crb enable && \
        dnf install -y bats \
    ; fi \
  ; fi

COPY "./geneos-xtender*.$PKG" ./
RUN if [ "$PKG" = "deb" ] ; then \
      apt-get install -y ./geneos-xtender*.deb \
  ; elif [ "$PKG" = "rpm" ] ; then \
      dnf install -y ./geneos-xtender*.rpm \
  ; fi

COPY ./tests/bats/ ./tests/bats/

ENV BATS_DIR="tests/bats"
ENV BATS_EXT_URL="https://raw.githubusercontent.com/mbland/go-script-bash/master/lib/bats"

RUN curl $BATS_EXT_URL/assertion-test-helpers -o $BATS_DIR/assertion-test-helpers && \
curl $BATS_EXT_URL/assertions -o $BATS_DIR/assertions && \
curl $BATS_EXT_URL/background-process -o $BATS_DIR/background-process && \
curl $BATS_EXT_URL/helper-function -o $BATS_DIR/helper-function && \
curl $BATS_EXT_URL/helpers -o $BATS_DIR/helpers

CMD ["/usr/bin/bats", "--tap", "tests/bats/post_install.bats"]
