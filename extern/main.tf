locals {
  jenkins_namespace    = "jenkins"
  monitoring_namespace = "monitoring"
  app_namespace        = "evaluation-system"
  traefik_cluster_ip   = data.kubernetes_service.traefik.spec[0].cluster_ip
}

data "kubernetes_service" "traefik" {
  metadata {
    name      = "traefik"
    namespace = "kube-system"
  }
}

resource "kubernetes_namespace" "jenkins" {
  metadata {
    name = local.jenkins_namespace
  }
}

resource "kubernetes_namespace" "monitoring" {
  metadata {
    name = local.monitoring_namespace
  }
}

# Allow Jenkins (default SA in jenkins namespace) to deploy/patch monitoring stack
resource "kubernetes_cluster_role" "jenkins_monitoring_deployer" {
  metadata {
    name = "jenkins-monitoring-deployer"
  }

  rule {
    api_groups = ["monitoring.coreos.com"]
    resources  = ["servicemonitors", "podmonitors"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = [""]
    resources  = ["configmaps", "services", "serviceaccounts", "pods", "secrets", "nodes", "nodes/proxy"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  rule {
    api_groups = ["apps"]
    resources  = ["deployments", "daemonsets", "statefulsets"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }

  # Needed for promtail ClusterRole/ClusterRoleBinding in monitoring kustomize
  rule {
    api_groups = ["rbac.authorization.k8s.io"]
    resources  = ["clusterroles", "clusterrolebindings", "roles", "rolebindings"]
    verbs      = ["get", "list", "watch", "create", "update", "patch", "delete"]
  }
}

resource "kubernetes_cluster_role_binding" "jenkins_monitoring_deployer" {
  metadata {
    name = "jenkins-monitoring-deployer"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.jenkins_monitoring_deployer.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
  }
}

# Allow Jenkins default SA to exec into the registry pod (jenkins namespace only).
resource "kubernetes_role" "jenkins_registry_exec" {
  metadata {
    name      = "jenkins-registry-exec"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
  }

  rule {
    api_groups = [""]
    resources  = ["pods/exec"]
    verbs      = ["create"]
  }
}

resource "kubernetes_role_binding" "jenkins_registry_exec" {
  metadata {
    name      = "jenkins-registry-exec"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.jenkins_registry_exec.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "default"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
  }
}

resource "kubernetes_manifest" "letsencrypt_issuer" {
  manifest = {
    apiVersion = "cert-manager.io/v1"
    kind       = "ClusterIssuer"
    metadata = {
      name = "letsencrypt"
    }
    spec = {
      acme = {
        email  = var.acme_email
        server = "https://acme-v02.api.letsencrypt.org/directory"
        privateKeySecretRef = {
          name = "letsencrypt-key"
        }
        solvers = [
          {
            http01 = {
              ingress = {
                ingressClassName = "traefik"
                ingressTemplate = {
                  metadata = {
                    annotations = {
                      "traefik.ingress.kubernetes.io/router.entrypoints" = "web"
                      "traefik.ingress.kubernetes.io/router.tls"         = "false"
                      "traefik.ingress.kubernetes.io/router.priority"    = "1000"
                    }
                  }
                }
              }
            }
          }
        ]
      }
    }
  }
}

resource "kubernetes_manifest" "jenkins_https_redirect" {
  manifest = {
    apiVersion = "traefik.io/v1alpha1"
    kind       = "Middleware"
    metadata = {
      name      = "https-redirect"
      namespace = kubernetes_namespace.jenkins.metadata[0].name
    }
    spec = {
      redirectScheme = {
        scheme    = "https"
        permanent = true
      }
    }
  }
}

resource "kubernetes_manifest" "monitoring_https_redirect" {
  manifest = {
    apiVersion = "traefik.io/v1alpha1"
    kind       = "Middleware"
    metadata = {
      name      = "https-redirect"
      namespace = kubernetes_namespace.monitoring.metadata[0].name
    }
    spec = {
      redirectScheme = {
        scheme    = "https"
        permanent = true
      }
    }
  }
}

resource "helm_release" "jenkins" {
  name       = "jenkins"
  repository = "https://charts.jenkins.io"
  chart      = "jenkins"
  namespace  = kubernetes_namespace.jenkins.metadata[0].name
  version    = "5.8.110"

  values = [
    yamlencode({
      controller = {
        admin = {
          username = var.jenkins_admin_user
          password = var.jenkins_admin_password
        }
        image = {
          repository = "jenkins/jenkins"
          tag        = "2.528.2-lts-jdk17"
        }
        installPlugins = [
          "configuration-as-code",
          "git",
          "git-client",
          "workflow-aggregator",
          "workflow-basic-steps",
          "workflow-cps",
          "workflow-durable-task-step",
          "workflow-step-api",
          "pipeline-model-definition",
          "credentials",
          "credentials-binding",
          "ssh-credentials",
          "kubernetes",
          "kubernetes-credentials",
          "durable-task",
          "apache-httpcomponents-client-4-api"
        ]
        jenkinsUrl  = "https://${var.jenkins_domain}"
        serviceType = "ClusterIP"
        ingress = {
          enabled          = true
          hostName         = var.jenkins_domain
          ingressClassName = "traefik"
          annotations = {
            "cert-manager.io/cluster-issuer" = "letsencrypt"
            "traefik.ingress.kubernetes.io/router.entrypoints" = "web,websecure"
            "traefik.ingress.kubernetes.io/router.middlewares" = "jenkins-https-redirect@kubernetescrd"
            "traefik.ingress.kubernetes.io/router.tls"         = "true"
          }
          tls = [
            {
              secretName = "jenkins-tls"
              hosts      = [var.jenkins_domain]
            }
          ]
        }
        persistence = {
          size = var.jenkins_storage_size
        }
      }
    })
  ]

  depends_on = [kubernetes_manifest.letsencrypt_issuer]
}

resource "helm_release" "kube_prometheus_stack" {
  name       = "kube-prometheus-stack"
  repository = "https://prometheus-community.github.io/helm-charts"
  chart      = "kube-prometheus-stack"
  namespace  = kubernetes_namespace.monitoring.metadata[0].name
  version    = "79.11.0"

  values = [
    yamlencode({
      grafana = {
        adminPassword = var.grafana_admin_password
        ingress = {
          enabled          = true
          ingressClassName = "traefik"
          hosts            = [var.grafana_domain]
          annotations = {
            "cert-manager.io/cluster-issuer" = "letsencrypt"
            "traefik.ingress.kubernetes.io/router.entrypoints" = "web,websecure"
            "traefik.ingress.kubernetes.io/router.middlewares" = "monitoring-https-redirect@kubernetescrd"
            "traefik.ingress.kubernetes.io/router.tls"         = "true"
          }
          tls = [
            {
              secretName = "grafana-tls"
              hosts      = [var.grafana_domain]
            }
          ]
        }
      }
      prometheus = {
        ingress = {
          enabled = false
        }
      }
      alertmanager = {
        ingress = {
          enabled = false
        }
      }
    })
  ]

  depends_on = [kubernetes_manifest.letsencrypt_issuer]
}

resource "kubernetes_deployment" "buildkitd" {
  metadata {
    name      = "buildkitd"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
    labels = {
      app = "buildkitd"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "buildkitd"
      }
    }

    template {
      metadata {
        labels = {
          app = "buildkitd"
        }
      }

      spec {
        container {
          name  = "buildkitd"
          image = "moby/buildkit:latest" # or whatever version you prefer

          # Expose TCP endpoint for remote clients (Jenkins)
          args = [
            "--addr", "tcp://0.0.0.0:1234",
            "--oci-worker=true",
            "--containerd-worker=false",
          ]

          port {
            container_port = 1234
            name           = "buildkit"
          }

          security_context {
            privileged = true
          }

          # Simple cache directory inside the pod
          volume_mount {
            name       = "buildkit-cache"
            mount_path = "/var/lib/buildkit"
            read_only  = false
          }
        }

        volume {
          name = "buildkit-cache"

          empty_dir {}
        }
      }
    }
  }
}

resource "kubernetes_service" "buildkitd" {
  metadata {
    name      = "buildkit"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
    labels = {
      app = "buildkitd"
    }
  }

  spec {
    selector = {
      app = "buildkitd"
    }

    port {
      name        = "buildkit"
      port        = 1234
      target_port = 1234
      protocol    = "TCP"
    }

    type = "ClusterIP"
  }
}

resource "kubernetes_persistent_volume_claim" "registry" {
  metadata {
    name      = "registry-pvc"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
  }

  spec {
    access_modes = ["ReadWriteOnce"]

    resources {
      requests = {
        storage = "30Gi"
      }
    }
  }

  wait_until_bound = false
}

resource "kubernetes_deployment" "registry" {
  metadata {
    name      = "registry"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
    labels = {
      app = "registry"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "registry"
      }
    }

    template {
      metadata {
        labels = {
          app = "registry"
        }
      }

      spec {
        container {
          name  = "registry"
          image = "registry:2"

          env {
            name  = "REGISTRY_STORAGE_DELETE_ENABLED"
            value = "true"
          }

          resources {
            requests = {
              cpu    = "250m"
              memory = "512Mi"
            }
            limits = {
              cpu    = "1"
              memory = "1Gi"
            }
          }

          readiness_probe {
            http_get {
              path = "/v2/"
              port = 5000
            }

            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          liveness_probe {
            http_get {
              path = "/v2/"
              port = 5000
            }

            initial_delay_seconds = 10
            period_seconds        = 10
            timeout_seconds       = 5
            failure_threshold     = 3
          }

          port {
            container_port = 5000
            name           = "registry"
          }

          volume_mount {
            name       = "registry-storage"
            mount_path = "/var/lib/registry"
          }
        }

        volume {
          name = "registry-storage"

          persistent_volume_claim {
            claim_name = kubernetes_persistent_volume_claim.registry.metadata[0].name
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "registry" {
  metadata {
    name      = "registry"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
    labels = {
      app = "registry"
    }
  }

  spec {
    selector = {
      app = "registry"
    }

    port {
      name        = "registry"
      port        = 5000
      target_port = 5000
      protocol    = "TCP"
    }

    type = "ClusterIP"
  }
}

resource "kubernetes_ingress_v1" "registry" {
  metadata {
    name      = "registry"
    namespace = kubernetes_namespace.jenkins.metadata[0].name
    annotations = {
      "cert-manager.io/cluster-issuer" = "letsencrypt"
      "traefik.ingress.kubernetes.io/router.entrypoints" = "web,websecure"
      "traefik.ingress.kubernetes.io/router.middlewares" = "jenkins-https-redirect@kubernetescrd"
      "traefik.ingress.kubernetes.io/router.tls"         = "true"
    }
  }

  spec {
    ingress_class_name = "traefik"

    rule {
      host = var.registry_domain

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service.registry.metadata[0].name

              port {
                number = 5000
              }
            }
          }
        }
      }
    }

    tls {
      hosts       = [var.registry_domain]
      secret_name = "registry-tls"
    }
  }
}

resource "kubernetes_namespace" "evaluation_system" {
  metadata {
    name = local.app_namespace
  }
}

resource "kubernetes_ingress_v1" "api_gateway" {
  metadata {
    name      = "api-gateway"
    namespace = kubernetes_namespace.evaluation_system.metadata[0].name
    annotations = {
      "cert-manager.io/cluster-issuer" = "letsencrypt"
      "traefik.ingress.kubernetes.io/router.entrypoints" = "web,websecure"
      "traefik.ingress.kubernetes.io/router.middlewares" = "evaluation-system-https-redirect@kubernetescrd"
      "traefik.ingress.kubernetes.io/router.tls"         = "true"
    }
  }

  spec {
    ingress_class_name = "traefik"

    rule {
      host = var.api_gateway_domain

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = "api-gateway" # Service name in evaluation-system
              port {
                number = 80
              }
            }
          }
        }
      }
    }

    tls {
      hosts       = [var.api_gateway_domain]
      secret_name = "api-gateway-tls"
    }
  }
}

resource "kubernetes_role" "jenkins_deployer" {
  metadata {
    name      = "jenkins-deployer"
    namespace = kubernetes_namespace.evaluation_system.metadata[0].name
  }

  rule {
    api_groups = ["batch"]
    resources = [
      "jobs",
    ]
    verbs = [
      "get",
      "list",
      "watch",
      "create",
      "update",
      "patch",
      "delete",
    ]
  }

  rule {
    api_groups = [""]
    resources = [
      "services",
      "configmaps",
      "secrets",
      "pods",
      "pods/log",
    ]
    verbs = [
      "get",
      "list",
      "watch",
      "create",
      "update",
      "patch",
      "delete",
    ]
  }

  rule {
    api_groups = ["apps"]
    resources = [
      "deployments",
      "replicasets",
    ]
    verbs = [
      "get",
      "list",
      "watch",
      "create",
      "update",
      "patch",
      "delete",
    ]
  }

  rule {
    api_groups = ["autoscaling"]
    resources = [
      "horizontalpodautoscalers",
    ]
    verbs = [
      "get",
      "list",
      "watch",
      "create",
      "update",
      "patch",
      "delete",
    ]
  }

  rule {
    api_groups = ["networking.k8s.io"]
    resources = [
      "ingresses",
    ]
    verbs = [
      "get",
      "list",
      "watch",
      "create",
      "update",
      "patch",
      "delete",
    ]
  }

  rule {
    api_groups = ["traefik.io"]
    resources = [
      "middlewares",
    ]
    verbs = [
      "get",
      "list",
      "watch",
      "create",
      "update",
      "patch",
      "delete",
    ]
  }

  rule {
    api_groups = [""]
    resources = [
      "services",
      "configmaps",
      "secrets",
      "pods",
      "pods/log",
      "persistentvolumeclaims",
    ]
    verbs = [
      "get",
      "list",
      "watch",
      "create",
      "update",
      "patch",
      "delete",
    ]
  }
}

resource "kubernetes_role_binding" "jenkins_deployer_binding" {
  metadata {
    name      = "jenkins-deployer-binding"
    namespace = kubernetes_namespace.evaluation_system.metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.jenkins_deployer.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "default" # SA name in the jenkins namespace
    namespace = kubernetes_namespace.jenkins.metadata[0].name
  }
}

resource "kubernetes_cluster_role" "jenkins_namespace_reader" {
  metadata {
    name = "jenkins-namespace-reader"
  }

  rule {
    api_groups = [""]
    resources  = ["namespaces"]
    verbs = [
      "get",
      "list",
      "watch",
      "patch",
      "update",
      "create",
    ]
  }
}

resource "kubernetes_cluster_role_binding" "jenkins_namespace_reader_binding" {
  metadata {
    name = "jenkins-namespace-reader-binding"
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "ClusterRole"
    name      = kubernetes_cluster_role.jenkins_namespace_reader.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = "default" # same SA as in the error: jenkins:default
    namespace = kubernetes_namespace.jenkins.metadata[0].name
  }
}
