variable "kubeconfig_path" {
  type        = string
  description = "Path to the kubeconfig produced by Ansible bootstrap"
  default     = "~/.kube/burrito-k3s.yaml"
}

variable "jenkins_domain" {
  type        = string
  description = "Public hostname for Jenkins ingress"
  default     = "jenkins.burrito.deway.fr"
}

variable "acme_email" {
  type        = string
  description = "Email for Let's Encrypt registration"
  default     = "admin@burrito.deway.fr"
}

variable "grafana_domain" {
  type        = string
  description = "Public hostname for Grafana ingress"
  default     = "grafana.burrito.deway.fr"
}

variable "grafana_admin_password" {
  type        = string
  description = "Admin password for Grafana (kube-prometheus-stack)"
  sensitive   = true
  default     = "admin"
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

variable "jenkins_storage_size" {
  type        = string
  description = "Persistent volume size for Jenkins home"
  default     = "20Gi"
}

variable "microservice_domain" {
  type        = string
  description = "Public hostname for the sample microservice ingress"
  default     = "api.burrito.deway.fr"
}

variable "microservice_image" {
  type        = string
  description = "Container image for the sample microservice deployment"
  default     = "nginx:stable"
}

variable "microservice_replicas" {
  type        = number
  description = "Replica count for the sample microservice deployment"
  default     = 2
}

variable "burrito_repo_url" {
  type        = string
  description = "Git URL for the Burrito repository (used by the Jenkins pipeline)"
  default     = "https://github.com/deway-developpement/Burrito.git"
}

variable "burrito_repo_branch" {
  type        = string
  description = "Branch to build for the Burrito pipeline job"
  default     = "main"
}

variable "k8s_namespace" {
  type        = string
  description = "Kubernetes namespace for Burrito workloads"
  default     = "evaluation-system"
}

variable "registry_domain" {
  type        = string
  description = "Public hostname for the container registry ingress"
  default     = "registry.burrito.deway.fr"
}

variable "api_gateway_domain" {
  type        = string
  description = "Public hostname for the API Gateway ingress"
  default     = "api.burrito.deway.fr"
}
