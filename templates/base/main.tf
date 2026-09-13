# Adapted from https://raw.githubusercontent.com/coder/coder/v2.36.5/examples/templates/kubernetes/main.tf
# Trimmed to what sandcastle needs: fixed sandcastle/base image, Kata
# RuntimeClass, and a DinD sidecar for in-workspace container builds.
terraform {
  required_providers {
    coder = {
      source = "coder/coder"
    }
    kubernetes = {
      source = "hashicorp/kubernetes"
    }
  }
}

provider "coder" {
}

variable "use_kubeconfig" {
  type        = bool
  description = <<-EOF
  Use host kubeconfig? (true/false)

  Set this to false if the Coder host is itself running as a Pod on the same
  Kubernetes cluster as you are deploying workspaces to.

  Set this to true if the Coder host is running outside the Kubernetes cluster
  for workspaces.  A valid "~/.kube/config" must be present on the Coder host.
  EOF
  default     = false
}

variable "namespace" {
  type        = string
  description = "The Kubernetes namespace to create workspaces in (must exist prior to creating workspaces)."
  default     = "sandcastle-workspaces"
}

data "coder_parameter" "home_disk_size" {
  name         = "home_disk_size"
  display_name = "Home disk size"
  description  = "The size of the home disk in GB"
  default      = "10"
  type         = "number"
  icon         = "/emojis/1f4be.png"
  mutable      = false
  validation {
    min = 1
    max = 99999
  }
}

provider "kubernetes" {
  # Authenticate via ~/.kube/config or a Coder-specific ServiceAccount, depending on admin preferences
  config_path = var.use_kubeconfig == true ? "~/.kube/config" : null
}

data "coder_workspace" "me" {}
data "coder_workspace_owner" "me" {}

resource "coder_agent" "main" {
  os             = "linux"
  arch           = "amd64"
  startup_script = <<-EOT
    set -e
    code-server --auth none --bind-addr 127.0.0.1:13337 >/tmp/code-server.log 2>&1 &
  EOT

  metadata {
    display_name = "CPU Usage"
    key          = "0_cpu_usage"
    script       = "coder stat cpu"
    interval     = 10
    timeout      = 1
  }

  metadata {
    display_name = "RAM Usage"
    key          = "1_ram_usage"
    script       = "coder stat mem"
    interval     = 10
    timeout      = 1
  }

  metadata {
    display_name = "Home Disk"
    key          = "2_home_disk"
    script       = "coder stat disk --path $${HOME}"
    interval     = 60
    timeout      = 1
  }
}

resource "coder_app" "code-server" {
  agent_id     = coder_agent.main.id
  slug         = "code-server"
  display_name = "code-server"
  icon         = "/icon/code.svg"
  url          = "http://localhost:13337/?folder=/home/coder"
  subdomain    = false
  share        = "owner"

  healthcheck {
    url       = "http://localhost:13337/healthz"
    interval  = 3
    threshold = 10
  }
}

resource "kubernetes_persistent_volume_claim_v1" "home" {
  metadata {
    name      = "coder-${data.coder_workspace.me.id}-home"
    namespace = var.namespace
    labels = {
      "app.kubernetes.io/name"     = "coder-pvc"
      "app.kubernetes.io/instance" = "coder-pvc-${data.coder_workspace.me.id}"
      "app.kubernetes.io/part-of"  = "coder"
      "com.coder.resource"         = "true"
      "com.coder.workspace.id"     = data.coder_workspace.me.id
      "com.coder.workspace.name"   = data.coder_workspace.me.name
      "com.coder.user.id"          = data.coder_workspace_owner.me.id
      "com.coder.user.username"    = data.coder_workspace_owner.me.name
    }
    annotations = {
      "com.coder.user.email" = data.coder_workspace_owner.me.email
    }
  }
  wait_until_bound = false
  spec {
    access_modes = ["ReadWriteOnce"]
    resources {
      requests = {
        storage = "${data.coder_parameter.home_disk_size.value}Gi"
      }
    }
  }
}

resource "kubernetes_deployment_v1" "main" {
  count = data.coder_workspace.me.start_count
  depends_on = [
    kubernetes_persistent_volume_claim_v1.home
  ]
  wait_for_rollout = false
  metadata {
    name      = "coder-${data.coder_workspace.me.id}"
    namespace = var.namespace
    labels = {
      "app.kubernetes.io/name"     = "coder-workspace"
      "app.kubernetes.io/instance" = "coder-workspace-${data.coder_workspace.me.id}"
      "app.kubernetes.io/part-of"  = "coder"
      "com.coder.resource"         = "true"
      "com.coder.workspace.id"     = data.coder_workspace.me.id
      "com.coder.workspace.name"   = data.coder_workspace.me.name
      "com.coder.user.id"          = data.coder_workspace_owner.me.id
      "com.coder.user.username"    = data.coder_workspace_owner.me.name
    }
    annotations = {
      "com.coder.user.email" = data.coder_workspace_owner.me.email
    }
  }

  spec {
    replicas = 1
    selector {
      match_labels = {
        "app.kubernetes.io/name"     = "coder-workspace"
        "app.kubernetes.io/instance" = "coder-workspace-${data.coder_workspace.me.id}"
        "app.kubernetes.io/part-of"  = "coder"
        "com.coder.resource"         = "true"
        "com.coder.workspace.id"     = data.coder_workspace.me.id
        "com.coder.workspace.name"   = data.coder_workspace.me.name
        "com.coder.user.id"          = data.coder_workspace_owner.me.id
        "com.coder.user.username"    = data.coder_workspace_owner.me.name
      }
    }
    strategy {
      type = "Recreate"
    }

    template {
      metadata {
        labels = {
          "app.kubernetes.io/name"     = "coder-workspace"
          "app.kubernetes.io/instance" = "coder-workspace-${data.coder_workspace.me.id}"
          "app.kubernetes.io/part-of"  = "coder"
          "com.coder.resource"         = "true"
          "com.coder.workspace.id"     = data.coder_workspace.me.id
          "com.coder.workspace.name"   = data.coder_workspace.me.name
          "com.coder.user.id"          = data.coder_workspace_owner.me.id
          "com.coder.user.username"    = data.coder_workspace_owner.me.name
        }
      }
      spec {
        # kata-clh-runtime-rs is also enforced by admission on this
        # namespace; setting it here makes the template correct by
        # construction rather than relying on the reject path.
        runtime_class_name = "kata-clh-runtime-rs"

        # No API-server access from workspaces; any such request should alert.
        automount_service_account_token = false
        enable_service_links            = false

        container {
          name              = "dev"
          image             = "sandcastle/base:0.1.0"
          image_pull_policy = "Never" # no registry yet; image is imported straight into k3s containerd
          command           = ["sh", "-c", coder_agent.main.init_script]
          security_context {
            run_as_user = 1000
          }
          env {
            name  = "CODER_AGENT_TOKEN"
            value = coder_agent.main.token
          }
          resources {
            requests = {
              "cpu"    = "500m"
              "memory" = "1Gi"
            }
            limits = {
              "cpu"    = "2"
              "memory" = "4Gi"
            }
          }
          volume_mount {
            mount_path = "/home/coder"
            name       = "home"
            read_only  = false
          }
          volume_mount {
            mount_path = "/run/dind"
            name       = "docker-sock"
          }
        }

        container {
          name              = "dind"
          image             = "sandcastle/dind:0.1.0" # images/dind: loop-mounted ext4 for /var/lib/docker
          image_pull_policy = "Never"
          security_context {
            # Applies inside the Kata guest only: kata-deploy configures the
            # shim with privileged_without_host_devices, so this does not
            # grant host device access.
            privileged = true
          }
          # The Docker API is a unix socket on a volume shared with the dev
          # container, never TCP. When args start with a flag, the dind
          # entrypoint prepends its own --host=tcp://0.0.0.0:2375, which put
          # the API (root in this guest) on every pod network interface; args
          # starting with "dockerd" are passed through without defaults.
          # --group=1000 lets the coder user use the socket without sudo.
          args = ["dockerd", "--host=unix:///run/dind/docker.sock", "--group=1000"]
          env {
            name  = "DOCKER_TLS_CERTDIR"
            value = ""
          }
          resources {
            limits = {
              "memory" = "4Gi"
            }
          }
          volume_mount {
            mount_path = "/var/lib/docker-backing"
            name       = "docker"
            read_only  = false
          }
          volume_mount {
            mount_path = "/run/dind"
            name       = "docker-sock"
          }
        }

        # Memory medium is required, not a tuning choice: under Kata a default
        # emptyDir is a host directory shared into the guest over virtio-fs,
        # where a unix socket file is visible to both containers but refuses
        # connections. A memory-backed emptyDir is tmpfs inside the guest.
        volume {
          name = "docker-sock"
          empty_dir {
            medium     = "Memory"
            size_limit = "1Mi"
          }
        }

        volume {
          name = "home"
          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim_v1.home.metadata.0.name
            read_only  = false
          }
        }

        # Holds only the sparse ext4 image the dind sidecar loop-mounts at
        # /var/lib/docker. overlayfs rejects this virtio-fs volume directly
        # as an upper layer; see images/dind/Dockerfile.
        volume {
          name = "docker"
          empty_dir {
            size_limit = "25Gi"
          }
        }

        affinity {
          # Spread workspace pods evenly across nodes.
          pod_anti_affinity {
            preferred_during_scheduling_ignored_during_execution {
              weight = 1
              pod_affinity_term {
                topology_key = "kubernetes.io/hostname"
                label_selector {
                  match_expressions {
                    key      = "app.kubernetes.io/name"
                    operator = "In"
                    values   = ["coder-workspace"]
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
