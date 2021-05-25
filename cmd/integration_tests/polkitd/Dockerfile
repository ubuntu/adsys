FROM ubuntu

COPY cmd/adsysd/integration_tests/polkitd/dbus.conf /
COPY cmd/adsysd/integration_tests/polkitd/polkitd.sh /

ENV DEBIAN_FRONTEND=noninteractive
RUN \
   apt update && \
   apt install -y policykit-1 dbus

ENTRYPOINT ["/polkitd.sh"]
