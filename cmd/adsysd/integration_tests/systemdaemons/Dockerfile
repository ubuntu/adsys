FROM ubuntu


ENV DEBIAN_FRONTEND=noninteractive
# we need at least dbusmock 0.25 to use systemd template
RUN apt update && apt install -y polkitd dbus libglib2.0-bin python3-gi python3-dbus python3-dbusmock

COPY cmd/adsysd/integration_tests/systemdaemons/*.py /
COPY cmd/adsysd/integration_tests/systemdaemons/run_daemons /

ENTRYPOINT ["/run_daemons"]
