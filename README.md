# Terry the Terraformer

Python CLI tool to to build red team infrastructure using Terraform, Ansible, and Docker. Once deployed, all resources can be integrated into a [Nebula](https://github.com/slackhq/nebula) network for secure communications across nodes.

## Documentation

Most documentation can be found in the [Wiki](https://github.com/ezra-buckingham/terry-the-terraformer/wiki). If there is missing documentation or unclear documentation, please create GitHub issue.

## Getting Started

Getting started is relatively easy. Follow the [Getting Started](https://github.com/ezra-buckingham/terry-the-terraformer/wiki/Getting-Started) instructions to begin using Terry.

## Known Limitations / Issues

* Logging errors will NOT print the stack trace
* Hostnames can be too long to generate SSL certs with certbot
* No central managment of wildcard Certs
* UFW rules to containers must run both `ufw allow` and `ufw route allow` to allow ufw to manage the docker routes

## What's next?

* Adding a secrets management solution to Terry to allow for dynamic generation of secrets and automatic pushing of secrets to a secure place
