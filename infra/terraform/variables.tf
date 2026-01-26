variable "kubeconfig_path" {
  type        = string
  description = "Path to the kubeconfig for the cluster"
  default     = "~/.kube/burrito-k3s.yaml"
}

variable "semaphore_namespace" {
  type        = string
  description = "Namespace for Semaphore workloads"
  default     = "semaphore"
}

variable "jenkins_namespace" {
  type        = string
  description = "Namespace where Jenkins runs"
  default     = "jenkins"
}

variable "jenkins_service_account" {
  type        = string
  description = "ServiceAccount name used by Jenkins to deploy"
  default     = "default"
}

variable "semaphore_gateway_domain" {
  type        = string
  description = "Public hostname for the Semaphore Envoy gateway"
  default     = "api.burrito.deway.fr"
}

variable "tls_cluster_issuer" {
  type        = string
  description = "cert-manager ClusterIssuer name for TLS"
  default     = "letsencrypt"
}

variable "gateway_service_name" {
  type        = string
  description = "Kubernetes Service name for the gateway"
  default     = "envoy-gateway"
}

variable "gateway_service_port" {
  type        = number
  description = "Service port for the gateway"
  default     = 80
}

variable "jenkins_domain" {
  type        = string
  description = "Public hostname for Jenkins ingress"
  default     = "jenkins.burrito.deway.fr"
}

variable "jenkins_admin_user" {
  type        = string
  description = "Admin username for Jenkins controller"
  default     = "admin"
}

variable "jenkins_admin_password" {
  type        = string
  description = "Admin password for Jenkins controller"
  sensitive   = true
  default     = "admin"
}
