# Docker-in-Docker sidecar for Kata workspaces.
#
# Upstream docker:dind cannot keep /var/lib/docker on a Kubernetes volume under
# Kata: volumes are host directories shared into the guest over virtio-fs, and
# overlayfs refuses virtio-fs as an upper layer ("invalid argument"). This image
# formats a sparse ext4 file on that volume and loop-mounts it at
# /var/lib/docker, giving overlayfs a real block filesystem inside the guest
# while image layers stay on disk instead of in memory.
#
# e2fsprogs is baked in rather than installed at start so the sidecar needs no
# package repository at runtime, which an air-gapped cluster will not have.
FROM docker:29.8.0-dind

RUN apk add --no-cache e2fsprogs

COPY sandcastle-dind /usr/local/bin/sandcastle-dind

ENTRYPOINT ["sandcastle-dind"]
CMD ["dockerd"]
