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
    // JWT credentials are managed via Terraform (fixed IDs).
  }

  environment {
    BUILDKIT_VERSION = '0.26.2'
    KUBECTL_VERSION  = 'v1.34.1'

    BUILDKIT_HOST = 'tcp://buildkit:1234'
    REGISTRY_HOST = 'registry.burrito.deway.fr'
    REGISTRY_PUSH_HOST = 'registry.jenkins.svc.cluster.local:5000'

    SERVICES = 'auth-identity academics attendance beacon'
    MIGRATIONS_IMAGE = 'semaphore-migrations'
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

    stage('Build Migrations Image') {
      steps {
        container('builder') {
          sh """
            set -e
            echo \"Building migrations image\"
            buildctl \\
              --addr \"${env.BUILDKIT_HOST}\" \\
              build \\
              --frontend dockerfile.v0 \\
              --local context=. \\
              --local dockerfile=. \\
              --opt filename=docker/Dockerfile.migrations \\
              --output 'type=image,\"name=${env.REGISTRY_PUSH_HOST}/${env.MIGRATIONS_IMAGE}:${env.BUILD_NUMBER},${env.REGISTRY_PUSH_HOST}/${env.MIGRATIONS_IMAGE}:latest,${env.REGISTRY_HOST}/${env.MIGRATIONS_IMAGE}:${env.BUILD_NUMBER},${env.REGISTRY_HOST}/${env.MIGRATIONS_IMAGE}:latest\",push=true,registry.insecure=true'
          """
        }
      }
    }

    stage('Deploy') {
      steps {
        container('builder') {
          withCredentials([string(credentialsId: params.KUBECONFIG_CREDENTIALS_ID, variable: 'KUBECONFIG_CONTENT')]) {
            script {
              writeFile file: 'kubeconfig', text: env.KUBECONFIG_CONTENT
            }
            withEnv(["KUBECONFIG=${pwd()}/kubeconfig", "K8S_NAMESPACE=${params.K8S_NAMESPACE}"]) {
              sh '''
                set -e
                kubectl delete job postgres-init -n "${K8S_NAMESPACE}" --ignore-not-found
                kubectl delete job semaphore-migrations -n "${K8S_NAMESPACE}" --ignore-not-found
                kubectl apply -k .

                kubectl wait --for=condition=complete job/semaphore-migrations \
                  -n "${K8S_NAMESPACE}" --timeout=10m || {
                    kubectl logs job/semaphore-migrations -n "${K8S_NAMESPACE}" --all-containers --tail=-1 || true
                    kubectl describe job semaphore-migrations -n "${K8S_NAMESPACE}" || true
                    exit 1
                  }
                kubectl apply -k k8s/monitoring
                kubectl apply -k k8s/istio
                kubectl rollout restart statefulset/postgres statefulset/redis -n "${K8S_NAMESPACE}"

                PROM_STS="prometheus-kube-prometheus-stack-prometheus"
                if kubectl -n monitoring get sts "${PROM_STS}" >/dev/null 2>&1; then
                  CURRENT=$(kubectl -n monitoring get sts "${PROM_STS}" -o jsonpath='{.spec.template.metadata.annotations.sidecar\\.istio\\.io/inject}' 2>/dev/null || true)
                  if [ "${CURRENT}" != "true" ]; then
                    kubectl -n monitoring patch sts "${PROM_STS}" \
                      -p '{"spec":{"template":{"metadata":{"annotations":{"sidecar.istio.io/inject":"true"}}}}}'
                    kubectl -n monitoring rollout status sts "${PROM_STS}" --timeout=5m || true
                  fi
                fi
              '''

              withCredentials([
                string(credentialsId: 'semaphore-jwt-private-key', variable: 'JWT_PRIVATE_KEY'),
                string(credentialsId: 'semaphore-jwt-public-key', variable: 'JWT_PUBLIC_KEY'),
                string(credentialsId: 'semaphore-jwt-issuer', variable: 'JWT_ISSUER'),
              ]) {
                script {
                  writeFile file: 'jwt_private.pem', text: env.JWT_PRIVATE_KEY
                  writeFile file: 'jwt_public.pem', text: env.JWT_PUBLIC_KEY
                }
                sh '''
                  set -e

                  kubectl create secret generic jwt-secrets \
                    --from-file=jwt-private-key=jwt_private.pem \
                    --from-file=jwt-public-key=jwt_public.pem \
                    --from-literal=jwt-issuer="${JWT_ISSUER}" \
                    --dry-run=client -o yaml | kubectl apply -n "${K8S_NAMESPACE}" -f -
                '''
              }

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
}
