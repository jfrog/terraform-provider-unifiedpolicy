terraform {
  required_providers {
    unifiedpolicy = {
      source  = "jfrog/unifiedpolicy"
      version = "1.0.0"
    }
  }
}

provider "unifiedpolicy" {
  url = "https://myinstance.jfrog.io/artifactory"
  // supply JFROG_ACCESS_TOKEN (Identity Token with Admin privileges) as env var
}

