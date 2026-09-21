FROM ros:melodic-ros-base-bionic@sha256:b4366ca0536e2ad3654ed66fb4475bc43b7a0c15bd8a5be91fd5ac9dfaf935d0
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python-scapy python-dpkt python-wxgtk3.0 && rm -rf /var/lib/apt/lists/*
WORKDIR /project
ENV PYTHONDONTWRITEBYTECODE=1
