pipeline {
  agent {
    kubernetes {
      yaml """
        apiVersion: v1
        kind: Pod
        spec:
          containers:
          - name: builder
            image: node:18-bullseye
            tty: true
            command: ["cat"]
        """
    }
  }

  options {
    timeout(time: 30, unit: 'MINUTES')
  }

  parameters {
    booleanParam(name: 'FORCE_BUILD_ALL', defaultValue: true, description: 'Build all images for Semaphore.')
    string(
      name: 'K8S_NAMESPACE',
      defaultValue: 'semaphore',
      description: 'Namespace where Semaphore is deployed.'
    )
    string(
      name: 'KUBECONFIG_CREDENTIALS_ID',
      defaultValue: 'kubeconfig-burrito',
      description: 'Jenkins file credential ID containing kubeconfig.'
    )
  }

  environment {
    BUILDKIT_VERSION = '0.26.2'
    KUBECTL_VERSION  = 'v1.34.1'

    BUILDKIT_HOST = 'tcp://buildkit:1234'
    REGISTRY_HOST = 'registry.burrito.deway.fr'
    REGISTRY_PUSH_HOST = 'registry.jenkins.svc.cluster.local:5000'

    SERVICES = 'auth-identity academics attendance beacon'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }

    stage('Install Build Tools') {
      steps {
        container('builder') {
          sh '''
            set -e
            if ! command -v buildctl >/dev/null 2>&1; then
              echo "Installing buildctl..."
              curl -sL "https://github.com/moby/buildkit/releases/download/v${BUILDKIT_VERSION}/buildkit-v${BUILDKIT_VERSION}.linux-amd64.tar.gz" \
                | tar -xz -C /usr/local
            fi

            if ! command -v kubectl >/dev/null 2>&1; then
              echo "Installing kubectl..."
              curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
              install -m 0755 kubectl /usr/local/bin/kubectl
              rm kubectl
            fi
          '''
        }
      }
    }

    stage('Build Images') {
      steps {
        container('builder') {
          script {
            def tasks = [:]
            def services = (env.SERVICES ?: '').tokenize(' ')

            services.each { svc ->
              def serviceName = svc
              tasks["build-${serviceName}"] = {
                sh """
                  set -e
                  echo "Building service: ${serviceName}"
                  buildctl \
                    --addr "${env.BUILDKIT_HOST}" \
                    build \
                    --frontend dockerfile.v0 \
                    --local context=. \
                    --local dockerfile=. \
                    --opt filename=docker/Dockerfile.go-service \
                    --opt "build-arg:SERVICE_DIR=services/${serviceName}" \
                    --output 'type=image,"name=${env.REGISTRY_PUSH_HOST}/semaphore-${serviceName}:${env.BUILD_NUMBER},${env.REGISTRY_PUSH_HOST}/semaphore-${serviceName}:latest",push=true,registry.insecure=true'
                """
              }
            }

            if (tasks.isEmpty()) {
              echo 'No images to build.'
            } else {
              parallel tasks
            }
          }
        }
      }
    }

    stage('Deploy') {
      steps {
        container('builder') {
          withCredentials([file(credentialsId: params.KUBECONFIG_CREDENTIALS_ID, variable: 'KUBECONFIG')]) {
            sh '''
              set -e
              kubectl apply -f k8s/semaphore-stack.yaml
            '''

            script {
              def services = (env.SERVICES ?: '').tokenize(' ')
              def updateImage = { String deployment, String image ->
                sh """
                  kubectl set image deployment/${deployment} \
                    ${deployment}=${env.REGISTRY_HOST}/${image}:${env.BUILD_NUMBER} \
                    -n "${params.K8S_NAMESPACE}"
                """
              }
              def restart = { String deployment ->
                sh """
                  kubectl rollout restart deployment/${deployment} -n "${params.K8S_NAMESPACE}"
                """
              }
              def rollout = { String deployment ->
                sh """
                  kubectl rollout status deployment/${deployment} -n "${params.K8S_NAMESPACE}" --timeout=5m
                """
              }

              services.each { svc ->
                updateImage(svc, "semaphore-${svc}")
                restart(svc)
              }

              services.each { svc ->
                rollout(svc)
              }
            }
          }
        }
      }
    }
  }
}
