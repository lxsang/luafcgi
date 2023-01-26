// rustup target add aarch64-unknown-linux-gnu
// rustup target add armv7-unknown-linux-gnueabihf

def build_luad() {
    sh '''
    set -e
    echo $HOME
    export RUSTUP_HOME=$HOME/.rustup/
    export CARGO_HOME=$HOME/.cargo/
    source $HOME/.cargo/env
    cd $WORKSPACE
    mkdir -p build/$arch/opt/www/bin
    DESTDIR=$WORKSPACE/build/$arch/opt/www/bin
    target="x86_64-unknown-linux-gnu"
    case $arch in
        arm64)
            target="aarch64-unknown-linux-gnu"
            ;;

        arm)
            target="armv7-unknown-linux-gnueabihf"
            ;;
        *)
            ;;
        esac
        cargo build --target=$target --release
        file target/release/luad
    '''
}

pipeline {
    agent { node{ label'workstation' }}
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
