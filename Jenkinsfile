pipeline {
  agent any
  stages {
    stage('Build') {
      environment {
        ENGINE_PORT = '5001'
        PATROWL_ENGINE = 'nmap'
      }
      steps {
        dir(path: 'engines/')
        sh 'python3 -m pip install -r $PATROWL_ENGINE/requirements.txt'
        sh 'python3 -m pip install requests>=2.22.0'
      }
    }

    stage('Finish') {
      steps {
        echo 'Done'
      }
    }

  }
}