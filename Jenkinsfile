pipeline {
  agent any
  stages {
    stage('Install sources') {
      environment {
        ENGINE_PORT = '5001'
        PATROWL_ENGINE = 'nmap'
      }
      steps {
        sh 'python3 -m pip install -r ./engines/$PATROWL_ENGINE/requirements.txt'
        sh 'python3 -m pip install requests>=2.22.0'
        sh 'gunicorn engine-$PATROWL_ENGINE:app -b 0.0.0.0:1$ENGINE_PORT --chdir engines/$PATROWL_ENGINE > /dev/null &'
      }
    }

    stage('Build Docker') {
      environment {
        ENGINE_PORT = '5001'
        PATROWL_ENGINE = 'nmap'
      }
      steps {
        sh 'docker --version'
        sh 'docker stop patrowl-$PATROWL_ENGINE || true'
        sh 'docker build --tag patrowl-$PATROWL_ENGINE engines/$PATROWL_ENGINE'
      }
    }

    stage('Run Docker') {
      environment {
        ENGINE_PORT = '5001'
        PATROWL_ENGINE = 'nmap'
      }
      steps {
        sh 'netstat -tulpn'
        sh 'docker ps -a'
        sh 'docker run -d --rm --name patrowl-$PATROWL_ENGINE -p $ENGINE_PORT:$ENGINE_PORT patrowl-$PATROWL_ENGINE'
      }
    }

    stage('Run Tests') {
      environment {
        ENGINE_PORT = '5001'
        PATROWL_ENGINE = 'nmap'
      }
      steps {
        sh 'netstat -tulpn'
        sh 'docker ps -a'
        sh 'pytest -s engines/$PATROWL_ENGINE/tests/test_*.py'
      }
    }

    stage('Finish') {
      steps {
        sh 'docker images'
      }
    }

  }
}