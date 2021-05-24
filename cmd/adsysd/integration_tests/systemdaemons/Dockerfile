FROM ubuntu

COPY cmd/adsysd/integration_tests/systemdaemons/dbus.conf /
COPY cmd/adsysd/integration_tests/systemdaemons/systemdaemons.sh /

ENV DEBIAN_FRONTEND=noninteractive
RUN \
   apt update && \
   apt install -y policykit-1 dbus libglib2.0-bin python3-dbusmock

ENTRYPOINT ["/systemdaemons.sh"]
