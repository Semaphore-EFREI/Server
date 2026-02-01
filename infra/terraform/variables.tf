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

variable "semaphore_gateway_domain" {
  type        = string
  description = "Public hostname for the Semaphore gateway"
  default     = "semaphore.deway.fr"
}

variable "tls_cluster_issuer" {
  type        = string
  description = "cert-manager ClusterIssuer name for TLS"
  default     = "letsencrypt"
}

variable "istio_namespace" {
  type        = string
  description = "Namespace for Istio control plane"
  default     = "istio-system"
}

variable "envoy_gateway_namespace" {
  type        = string
  description = "Namespace for Envoy Gateway data plane services"
  default     = "envoy-gateway-system"
}

variable "envoy_gateway_chart_version" {
  type        = string
  description = "Envoy Gateway Helm chart version"
  default     = "v0.0.0-latest"
}

variable "istio_chart_version" {
  type        = string
  description = "Istio chart version (base, istiod, gateway)"
  default     = "1.23.2"
}

variable "istio_ingressgateway_service_type" {
  type        = string
  description = "Service type for Istio ingress gateway"
  default     = "ClusterIP"
}

variable "semaphore_repo_url" {
  type        = string
  description = "Git URL for the Semaphore repository (used by the Jenkins pipeline)"
  default     = "https://github.com/Semaphore-EFREI/Server"
}

variable "semaphore_repo_branch" {
  type        = string
  description = "Branch to build for the Semaphore pipeline job"
  default     = "main"
}

variable "semaphore_jenkinsfile_path" {
  type        = string
  description = "Path to the Jenkinsfile inside the Semaphore repo"
  default     = "Jenkinsfile"
}

variable "semaphore_jenkins_job_name" {
  type        = string
  description = "Jenkins job name for Semaphore"
  default     = "semaphore-backend"
}

variable "semaphore_jwt_private_key" {
  type        = string
  description = "JWT private key PEM for Semaphore"
  sensitive   = true
  default     = "replace-me"
}

variable "semaphore_jwt_public_key" {
  type        = string
  description = "JWT public key PEM for Semaphore"
  sensitive   = true
  default     = "replace-me"
}

variable "semaphore_jwt_issuer" {
  type        = string
  description = "JWT issuer for Semaphore"
  default     = "semaphore-auth-identity"
}
