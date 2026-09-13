# sandcastle/base: workspace image for code-server + DinD sidecar dev.
# Kept generic here; the Kata/Cilium/admission boundary is enforced outside
# the image (RuntimeClass, network policy, admission policy).
FROM ubuntu:26.04

ARG CODE_SERVER_VERSION=4.137.0

# Docker CLI only — the daemon runs in the DinD sidecar and is reached over
# DOCKER_HOST below.
COPY --from=docker:29.8.0-cli /usr/local/bin/docker /usr/local/bin/docker

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      git \
      sudo \
      bash-completion \
      build-essential \
      python3 \
      python3-pip \
      python3-venv \
      nodejs \
      npm \
      openssh-client \
      jq \
      less \
      vim-tiny \
      locales \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /tmp/code-server.deb \
      "https://github.com/coder/code-server/releases/download/v${CODE_SERVER_VERSION}/code-server_${CODE_SERVER_VERSION}_amd64.deb" \
    && apt-get install -y --no-install-recommends /tmp/code-server.deb \
    && rm -f /tmp/code-server.deb

# ubuntu:26.04 ships a uid-1000 user named "ubuntu"; remove it so uid 1000 is
# free for the coder user, which every workspace template assumes.
RUN if id -u ubuntu >/dev/null 2>&1; then userdel -r ubuntu; fi \
    && useradd -m -u 1000 -s /bin/bash coder

# The agent already has root-equivalent power inside its Kata VM; containment
# is the VM and network, not in-guest sudo.
RUN echo "coder ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/coder \
    && chmod 0440 /etc/sudoers.d/coder

# Applied last so the image still builds on the host against public mirrors;
# workspaces only know the in-cluster Nexus mirror. Phase 3 egress lockdown
# makes that the only reachable path anyway.
COPY mirror/ /

ENV DOCKER_HOST=unix:///run/dind/docker.sock

USER coder
WORKDIR /home/coder
