def build_luad() {
    sh '''#!/bin/bash
    set -e
    export RUSTUP_HOME=/opt/rust/rustup
    export CARGO_HOME=/opt/rust/cargo
    . /opt/rust/cargo/env
    cd $WORKSPACE
    TARGET=
    case "$arch" in
        amd64)
            TARGET="x86_64-unknown-linux-gnu"
            ;;
        arm64)
            TARGET="aarch64-unknown-linux-gnu"
            ;;
        arm)
            TARGET="armv7-unknown-linux-gnueabihf"
            ;;
        *)
            echo "unknown target for architecture $arch"
            exit 1
            ;;
    esac
    rustup target add $TARGET
    mkdir -p build/$arch/opt/www/bin
    DESTDIR=$WORKSPACE/build/$arch/opt/www/bin
    cargo build --target=$TARGET --release
    cp target/$TARGET/release/luad $DESTDIR
  '''
}

pipeline {
    agent { node { label'master' } }
    options {
        // Limit build history with buildDiscarder option:
        // daysToKeepStr: history is only kept up to this many days.
        // numToKeepStr: only this many build logs are kept.
        // artifactDaysToKeepStr: artifacts are only kept up to this many days.
        // artifactNumToKeepStr: only this many builds have their artifacts kept.
        buildDiscarder(logRotator(numToKeepStr: '1'))
        // Enable timestamps in build log console
        timestamps()
        // Maximum time to run the whole pipeline before canceling it
        timeout(time: 3, unit: 'HOURS')
        // Use Jenkins ANSI Color Plugin for log console
        ansiColor('xterm')
        // Limit build concurrency to 1 per branch
        disableConcurrentBuilds()
    }
    stages
  {
        stage('Prepare dependencies')
    {
            steps {
                copyArtifacts(projectName: 'gitea-sync/ant-http/master', target: 'antd')
            }
    }
        stage('Build AMD64') {
            steps {
                script {
                    env.arch = 'amd64'
                }
                build_luad()
            }
        }
        stage('Build ARM64') {
            steps {
                script {
                    env.arch = 'arm64'
                }
                build_luad()
            }
        }
        stage('Build ARM') {
            steps {
                script {
                    env.arch = 'arm'
                }
                build_luad()
            }
        }
        stage('Archive') {
            steps {
                script {
                    archiveArtifacts artifacts: 'build/', fingerprint: true
                }
            }
        }
  }
}
