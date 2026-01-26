resource "jenkins_credential_secret_text" "kubeconfig" {
  name        = "kubeconfig-burrito"
  description = "Kubeconfig for Burrito cluster"
  secret      = file(pathexpand(var.kubeconfig_path))
}

resource "jenkins_credential_secret_text" "database_username" {
  name        = "burrito-database-username"
  description = "Database username for Burrito services"
  secret      = var.burrito_database_username
}

resource "jenkins_credential_secret_text" "database_password" {
  name        = "burrito-database-password"
  description = "Database password for Burrito services"
  secret      = var.burrito_database_password
}

resource "jenkins_credential_secret_text" "jwt_secret" {
  name        = "burrito-jwt-secret"
  description = "JWT signing secret for Burrito services"
  secret      = var.burrito_jwt_secret
}

resource "jenkins_credential_secret_text" "jwt_expires_in" {
  name        = "burrito-jwt-expires-in"
  description = "JWT access token TTL"
  secret      = var.burrito_jwt_expires_in
}

resource "jenkins_credential_secret_text" "jwt_refresh_expires_in" {
  name        = "burrito-jwt-refresh-expires-in"
  description = "JWT refresh token TTL"
  secret      = var.burrito_jwt_refresh_expires_in
}

resource "jenkins_credential_secret_text" "smtp_user" {
  name        = "burrito-smtp-user"
  description = "SMTP user or API key for outbound email"
  secret      = var.burrito_smtp_user
}

resource "jenkins_credential_secret_text" "smtp_pass" {
  name        = "burrito-smtp-pass"
  description = "SMTP password or API secret for outbound email"
  secret      = var.burrito_smtp_pass
}

resource "jenkins_credential_secret_text" "huggingface_hub_token" {
  name        = "burrito-huggingface-hub-token"
  description = "Hugging Face Hub token for intelligence-ms"
  secret      = var.burrito_huggingface_hub_token
}

resource "jenkins_job" "burrito_backend" {
  name = "burrito-backend"

  // Jenkinsfile-from-SCM job definition
  template = templatefile("${path.module}/jenkins-pipeline.xml", {
    repo_url         = var.burrito_repo_url
    branch           = var.burrito_repo_branch
    jenkinsfile_path = "Jenkinsfile"
    k8s_namespace    = var.k8s_namespace
  })

  depends_on = [
    jenkins_credential_secret_text.kubeconfig,
    jenkins_credential_secret_text.database_username,
    jenkins_credential_secret_text.database_password,
    jenkins_credential_secret_text.jwt_secret,
    jenkins_credential_secret_text.jwt_expires_in,
    jenkins_credential_secret_text.jwt_refresh_expires_in,
    jenkins_credential_secret_text.smtp_user,
    jenkins_credential_secret_text.smtp_pass,
    jenkins_credential_secret_text.huggingface_hub_token,
  ]
}

resource "jenkins_job" "burrito_seed_analytics" {
  name = "burrito-seed-analytics"

  template = templatefile("${path.module}/jenkins-pipeline.xml", {
    repo_url         = var.burrito_repo_url
    branch           = var.burrito_repo_branch
    jenkinsfile_path = "backend/Jenkinsfile.seed-analytics"
    k8s_namespace    = var.k8s_namespace
  })

  depends_on = [jenkins_credential_secret_text.kubeconfig]
}

resource "jenkins_job" "burrito_cleanup_registry" {
  name = "burrito-cleanup-registry"

  template = templatefile("${path.module}/jenkins-pipeline-cleanup.xml", {
    repo_url         = var.burrito_repo_url
    branch           = var.burrito_repo_branch
    jenkinsfile_path = "Jenkinsfile.cleanup-registry"
  })
}
