FROM ubuntu


ENV DEBIAN_FRONTEND=noninteractive
# we need at least dbusmock 0.25 to use systemd template
RUN \
   apt-get update && \
   apt-get install -y policykit-1 dbus libglib2.0-bin python3-pip python3-gi python3-dbus && \
   pip install python-dbusmock

COPY cmd/adsysd/integration_tests/systemdaemons/*.py /
COPY cmd/adsysd/integration_tests/systemdaemons/run_daemons /

ENTRYPOINT ["/run_daemons"]
