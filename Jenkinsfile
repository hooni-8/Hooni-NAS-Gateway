// Uses Declarative syntax to run commands inside a container.
pipeline {

   agent {
        node {
            label 'kaniko-pod'
        }
   }

	environment {
		IMAGE_PATH = "nas"
		REPLACE_NAME = "nas-gateway"
		IMAGE_NAME = "${REPLACE_NAME}:v"
		IMAGE_VERSION = "0.0.${BUILD_NUMBER}"

		ARGOCD_GIT_URL = "github.com/hooni-8/argocd.git"
		ARGOCD_GIT_BRANCH = "main"
		ARGOCD_DEPLOY_YAML_FILE = "NAS/NAS-gateway/deployment.yaml"
	}

	stages {
		stage('Build Gradle') {
			steps {
				container('kaniko') {
					sh 'chmod +x gradlew'
					sh './gradlew clean build -x test -PbuildNumber="$BUILD_NUMBER" -PbranchName="$gitlabBranch" --info > gradle.log'
				}
			}

			post {
				failure {
					echo 'Building js & jar failed...'
					updateGitlabCommitStatus name: 'build', state: 'failed'
				}
				success {
					echo 'Building js & jar succeeded...'
					updateGitlabCommitStatus name: 'build', state: 'success'
				}
        	}
        }

		stage('Build & Push Image') {
            steps {
                container('kaniko') {
                    sh """
                        /kaniko/executor --context `pwd` \
                                         --dockerfile `pwd`/Dockerfile \
                                         --destination docker.hooni.co.kr/${IMAGE_PATH}/${IMAGE_NAME}${IMAGE_VERSION}
                    """
                }
            }

			post {
				failure {
					echo 'Building image & push failed...'
					updateGitlabCommitStatus name: 'image', state: 'failed'
				}
				success {
					echo 'Building image & push succeeded...'
					updateGitlabCommitStatus name: 'image', state: 'success'
				}
			}
		}

		stage('Update ArgoCD Manifest') {
            steps {
                sh "mkdir argocd"

                dir("argocd"){
                    git credentialsId: "github-api-token", url: "https://${ARGOCD_GIT_URL}", branch: "${ARGOCD_GIT_BRANCH}"

                    sh "git config user.email 'lee990726@gmail.com'"
                    sh "git config user.name 'Hooni'"
                    sh "sed -i 's/${REPLACE_NAME}:.*\$/${IMAGE_NAME}${IMAGE_VERSION}/g' ${ARGOCD_DEPLOY_YAML_FILE}"
                    sh "git add ${ARGOCD_DEPLOY_YAML_FILE}"
                    sh "git commit -m '[UPDATE] docker image info -> ${IMAGE_NAME}${IMAGE_VERSION}'"

                    withCredentials([usernamePassword(credentialsId: "github-api-token", passwordVariable: 'GIT_PASSWORD', usernameVariable: 'GIT_USERNAME')]) {
                        sh("git push https://${GIT_USERNAME}:${GIT_PASSWORD}@${ARGOCD_GIT_URL}")
                    }
                }
            }

            post {
                failure {
                    echo 'Updating ArgoCD manifest failed...'
                    updateGitlabCommitStatus name: 'deploy', state: 'failed'
                }
                success {
                    echo 'Updating ArgoCD manifest succeeded...'
                    updateGitlabCommitStatus name: 'deploy', state: 'success'
                }
                always {
                    cleanWs(deleteDirs: true, disableDeferredWipeout: true)
                }
            }
        }
	}
}