resource "jenkins_job" "semaphore_backend" {
  name = var.semaphore_jenkins_job_name

  template = templatefile("${path.module}/jenkins-pipeline.xml", {
    repo_url         = var.semaphore_repo_url
    branch           = var.semaphore_repo_branch
    jenkinsfile_path = var.semaphore_jenkinsfile_path
  })
}
