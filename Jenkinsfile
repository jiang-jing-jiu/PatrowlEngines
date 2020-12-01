pipeline {
  agent any
  stages {
    stage('Build') {
      environment {
        ENGINE_PORT = '5001'
        PATROWL_ENGINE = 'nmap'
      }
      steps {
        sh 'python3 -m pip install -r ./engines/$PATROWL_ENGINE/requirements.txt'
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