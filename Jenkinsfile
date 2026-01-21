pipeline {
	agent any

	environment {
		// Docker repositories
		TEST_REGISTRY = 'rg.fr-par.scw.cloud/testing-images'
		REGISTRY = 'rg.fr-par.scw.cloud/app-images'

		// Images
		PHP_TEST_IMAGE = 'php:8.5'

		// Workspace directory inside container
		CONTAINER_WORKSPACE = '/workspace'
	}

	stages {
		stage('Docker Login') {
			steps {
				script {
					withCredentials([string(credentialsId: 'scaleway_secret_key', variable: 'SECRET')]) {
						sh '''
							echo "$SECRET" | docker login $TEST_REGISTRY -u nologin --password-stdin
						'''
					}
				}
			}
		}

		stage('Pull Test Image') {
			steps {
				sh "docker pull ${TEST_REGISTRY}/${PHP_TEST_IMAGE}"
			}
		}

		stage('Install Dependencies') {
			steps {
				script {
					sh """
						docker run --rm \
							-v \$(pwd):${CONTAINER_WORKSPACE} \
							-w ${CONTAINER_WORKSPACE} \
							${TEST_REGISTRY}/${PHP_TEST_IMAGE} \
							composer update && composer install --prefer-dist --no-progress --no-interaction --optimize-autoloader
					"""
				}
			}
		}

		stage('Verify Dependencies') {
			steps {
				script {
					sh """
						docker run --rm \
							-v \$(pwd):${CONTAINER_WORKSPACE} \
							-w ${CONTAINER_WORKSPACE} \
							${TEST_REGISTRY}/${PHP_TEST_IMAGE} \
							composer validate --strict
					"""
				}
			}
		}

		stage('Testing') {
			parallel {

				stage('Code Style Check (PHPCS)') {
					steps {
						script {
							sh """
								docker run --rm \
									-v \$(pwd):${CONTAINER_WORKSPACE} \
									-w ${CONTAINER_WORKSPACE} \
									${TEST_REGISTRY}/${PHP_TEST_IMAGE} \
									./vendor/bin/pint --test
							"""
						}
					}
				}

				stage('Static Analysis (PHPStan)') {
					steps {
						script {
							sh """
								docker run --rm \
									-v \$(pwd):${CONTAINER_WORKSPACE} \
									-w ${CONTAINER_WORKSPACE} \
									${TEST_REGISTRY}/${PHP_TEST_IMAGE} \
									./vendor/bin/phpstan analyse --memory-limit=2G
							"""
						}
					}
				}

				stage('Run Tests (PHPUnit)') {
					steps {
						script {
							sh """
						docker run --rm \
							-v \$(pwd):${CONTAINER_WORKSPACE} \
							-w ${CONTAINER_WORKSPACE} \
							${TEST_REGISTRY}/${PHP_TEST_IMAGE} \
							sh -c 'composer test'
					"""
						}
					}
				}

			}
		}

		stage('Trigger Satis rebuild') {
			steps {
				build job: 'internal/eSoul Internal/packages-repository/master', wait: false
			}
		}
	}
}