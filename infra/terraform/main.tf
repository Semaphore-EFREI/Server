locals {
  app_namespace     = var.semaphore_namespace
  gateway_namespace = var.envoy_gateway_namespace
}

resource "kubernetes_namespace" "semaphore" {
  metadata {
    name = local.app_namespace
    labels = {
      "istio-injection" = "enabled"
    }
  }
}

resource "kubernetes_namespace" "envoy_gateway_system" {
  metadata {
    name = local.gateway_namespace
    labels = {
      "istio-injection" = "enabled"
    }
  }
}

resource "kubernetes_manifest" "semaphore_https_redirect" {
  manifest = {
    apiVersion = "traefik.io/v1alpha1"
    kind       = "Middleware"
    metadata = {
      name      = "semaphore-https-redirect"
      namespace = var.istio_namespace
    }
    spec = {
      redirectScheme = {
        scheme    = "https"
        permanent = true
      }
    }
  }
}

resource "kubernetes_manifest" "semaphore_api_cors" {
  manifest = {
    apiVersion = "traefik.io/v1alpha1"
    kind       = "Middleware"
    metadata = {
      name      = "semaphore-api-cors"
      namespace = local.gateway_namespace
    }
    spec = {
      headers = {
        accessControlAllowCredentials = true
        accessControlAllowHeaders = [
          "authorization",
          "content-type",
          "x-device-id",
          "x-student-id",
          "x-course-id",
          "idempotency-key",
        ]
        accessControlAllowMethods = [
          "GET",
          "POST",
          "PUT",
          "PATCH",
          "DELETE",
          "OPTIONS",
        ]
        accessControlAllowOriginList = [
          "https://semaphore.lebonnec.uk",
          "https://semaphore.deway.fr",
          "https://app.semaphore.deway.fr",
          "http://localhost:3000",
          "http://localhost:5173",
        ]
        accessControlExposeHeaders = [
          "content-length",
        ]
        addVaryHeader = true
      }
    }
  }
}

resource "kubernetes_ingress_v1" "semaphore_gateway_http" {
  metadata {
    name      = "semaphore-gateway-http"
    namespace = local.gateway_namespace
    annotations = {
      "traefik.ingress.kubernetes.io/router.entrypoints" = "web"
      "traefik.ingress.kubernetes.io/router.middlewares" = "${var.istio_namespace}-semaphore-https-redirect@kubernetescrd,${local.gateway_namespace}-semaphore-api-cors@kubernetescrd"
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
              name = "envoy-semaphore-gateway"

              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace.envoy_gateway_system]
}

resource "kubernetes_ingress_v1" "semaphore_gateway_https" {
  metadata {
    name      = "semaphore-gateway-https"
    namespace = local.gateway_namespace
    annotations = {
      "cert-manager.io/cluster-issuer"                   = var.tls_cluster_issuer
      "traefik.ingress.kubernetes.io/router.entrypoints" = "websecure"
      "traefik.ingress.kubernetes.io/router.tls"         = "true"
      "traefik.ingress.kubernetes.io/router.middlewares" = "${local.gateway_namespace}-semaphore-api-cors@kubernetescrd"
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
              name = "envoy-semaphore-gateway"

              port {
                number = 80
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

  depends_on = [kubernetes_namespace.envoy_gateway_system]
}

resource "kubernetes_ingress_v1" "semaphore_frontend_http" {
  metadata {
    name      = "semaphore-frontend-http"
    namespace = local.app_namespace
    annotations = {
      "traefik.ingress.kubernetes.io/router.entrypoints" = "web"
      "traefik.ingress.kubernetes.io/router.middlewares" = "${var.istio_namespace}-semaphore-https-redirect@kubernetescrd"
    }
  }

  spec {
    ingress_class_name = "traefik"

    rule {
      host = var.semaphore_frontend_domain

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = "frontend"

              port {
                number = 80
              }
            }
          }
        }
      }
    }
  }
}

resource "kubernetes_ingress_v1" "semaphore_frontend_https" {
  metadata {
    name      = "semaphore-frontend-https"
    namespace = local.app_namespace
    annotations = {
      "cert-manager.io/cluster-issuer"                   = var.tls_cluster_issuer
      "traefik.ingress.kubernetes.io/router.entrypoints" = "websecure"
      "traefik.ingress.kubernetes.io/router.tls"         = "true"
    }
  }

  spec {
    ingress_class_name = "traefik"

    rule {
      host = var.semaphore_frontend_domain

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = "frontend"

              port {
                number = 80
              }
            }
          }
        }
      }
    }

    tls {
      hosts       = [var.semaphore_frontend_domain]
      secret_name = "semaphore-frontend-tls"
    }
  }
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

resource "kubernetes_namespace" "istio_system" {
  metadata {
    name = var.istio_namespace
  }
}

resource "helm_release" "istio_base" {
  name       = "istio-base"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "base"
  namespace  = var.istio_namespace
  version    = var.istio_chart_version

  depends_on = [kubernetes_namespace.istio_system]
}

resource "helm_release" "istiod" {
  name       = "istiod"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "istiod"
  namespace  = var.istio_namespace
  version    = var.istio_chart_version

  values = [
    yamlencode({
      meshConfig = {
        accessLogFile = "/dev/stdout"
      }
    }),
  ]

  depends_on = [helm_release.istio_base]
}

resource "helm_release" "istio_ingressgateway" {
  name       = "istio-ingressgateway"
  repository = "https://istio-release.storage.googleapis.com/charts"
  chart      = "gateway"
  namespace  = var.istio_namespace
  version    = var.istio_chart_version

  values = [
    yamlencode({
      service = {
        type = var.istio_ingressgateway_service_type
      }
    }),
  ]

  depends_on = [helm_release.istiod]
}

resource "helm_release" "envoy_gateway" {
  name       = "eg"
  repository = "oci://docker.io/envoyproxy"
  chart      = "gateway-helm"
  namespace  = var.envoy_gateway_namespace
  version    = var.envoy_gateway_chart_version

  values = [
    yamlencode({
      deployment = {
        pod = {
          annotations = {
            "sidecar.istio.io/inject" = "false"
          }
        }
      }
      certgen = {
        job = {
          pod = {
            annotations = {
              "sidecar.istio.io/inject" = "false"
            }
          }
        }
      }
    }),
  ]

  depends_on = [kubernetes_namespace.envoy_gateway_system, helm_release.istiod]
}
