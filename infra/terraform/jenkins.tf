resource "jenkins_credential_secret_text" "semaphore_jwt_private_key" {
  name        = "semaphore-jwt-private-key"
  description = "JWT private key PEM for Semaphore"
  secret      = var.semaphore_jwt_private_key
}

resource "jenkins_credential_secret_text" "semaphore_jwt_public_key" {
  name        = "semaphore-jwt-public-key"
  description = "JWT public key PEM for Semaphore"
  secret      = var.semaphore_jwt_public_key
}

resource "jenkins_credential_secret_text" "semaphore_jwt_issuer" {
  name        = "semaphore-jwt-issuer"
  description = "JWT issuer for Semaphore"
  secret      = var.semaphore_jwt_issuer
}

resource "jenkins_credential_secret_text" "semaphore_service_auth_token" {
  name        = "semaphore-service-auth-token"
  description = "Service auth token for internal gRPC calls"
  secret      = var.semaphore_service_auth_token
}

resource "jenkins_job" "semaphore_backend" {
  name = var.semaphore_jenkins_job_name

  template = templatefile("${path.module}/jenkins-pipeline.xml", {
    repo_url         = var.semaphore_repo_url
    branch           = var.semaphore_repo_branch
    jenkinsfile_path = var.semaphore_jenkinsfile_path
  })

  depends_on = [
    jenkins_credential_secret_text.semaphore_jwt_private_key,
    jenkins_credential_secret_text.semaphore_jwt_public_key,
    jenkins_credential_secret_text.semaphore_jwt_issuer,
    jenkins_credential_secret_text.semaphore_service_auth_token,
  ]
}

resource "jenkins_job" "semaphore_frontend" {
  name = var.semaphore_frontend_jenkins_job_name

  template = templatefile("${path.module}/jenkins-pipeline-frontend.xml", {
    repo_url = var.semaphore_frontend_repo_url
    branch   = var.semaphore_frontend_repo_branch
  })
}
