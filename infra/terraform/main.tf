locals {
  app_namespace = var.semaphore_namespace
}

resource "kubernetes_namespace" "semaphore" {
  metadata {
    name = local.app_namespace
  }
}

resource "kubernetes_manifest" "semaphore_https_redirect" {
  manifest = {
    apiVersion = "traefik.io/v1alpha1"
    kind       = "Middleware"
    metadata = {
      name      = "https-redirect"
      namespace = kubernetes_namespace.semaphore.metadata[0].name
    }
    spec = {
      redirectScheme = {
        scheme    = "https"
        permanent = true
      }
    }
  }
}

resource "kubernetes_ingress_v1" "semaphore_gateway" {
  metadata {
    name      = "semaphore-gateway"
    namespace = kubernetes_namespace.semaphore.metadata[0].name
    annotations = {
      "cert-manager.io/cluster-issuer"                  = var.tls_cluster_issuer
      "traefik.ingress.kubernetes.io/router.entrypoints" = "web,websecure"
      "traefik.ingress.kubernetes.io/router.middlewares" = "${var.semaphore_namespace}-https-redirect@kubernetescrd"
      "traefik.ingress.kubernetes.io/router.tls"         = "true"
    }
  }

  spec {
    ingress_class_name = "traefik"

    rule {
      host = var.semaphore_gateway_domain

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = var.gateway_service_name

              port {
                number = var.gateway_service_port
              }
            }
          }
        }
      }
    }

    tls {
      hosts       = [var.semaphore_gateway_domain]
      secret_name = "semaphore-gateway-tls"
    }
  }

  depends_on = [kubernetes_manifest.semaphore_https_redirect]
}

resource "kubernetes_role" "jenkins_deployer" {
  metadata {
    name      = "jenkins-deployer"
    namespace = kubernetes_namespace.semaphore.metadata[0].name
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
    namespace = kubernetes_namespace.semaphore.metadata[0].name
  }

  role_ref {
    api_group = "rbac.authorization.k8s.io"
    kind      = "Role"
    name      = kubernetes_role.jenkins_deployer.metadata[0].name
  }

  subject {
    kind      = "ServiceAccount"
    name      = var.jenkins_service_account
    namespace = var.jenkins_namespace
  }
}
