terraform {
  required_providers {
    aws = {
      source = "hashicorp/aws"
      version = "~> 5.54"
    }
  }
}

variable "pvt_key" {
  description = "The SSH private key for VPS access"
  type        = string
}

variable "public_key" {
  description = "Path to the public SSH key"
  type        = string
}

provider "aws" {
  shared_credentials_files = ["~/.aws/credentials"]
  region = "eu-north-1"
}
