
<p align="center">
  <img src="logos/terry_logo_basic_1000x1090_bg.png" width="350" title="Terry Logo">
</p>

# Terry the Terraformer

Python CLI tool to to build red team infrastructure using Terraform, Ansible, and Docker. Once deployed, all resources can be integrated into a [Nebula network](https://github.com/slackhq/nebula) for secure communications across nodes.

## Documentation

Most documentation can be found in the [Wiki pages](https://github.com/ezra-buckingham/terry-the-terraformer/wiki). If there is missing documentation or unclear documentation, please create GitHub issue.

## Getting Started

Getting started is relatively easy. Follow the [Getting Started](https://github.com/ezra-buckingham/terry-the-terraformer/wiki/Getting-Started) instructions to begin using Terry.

## Contributors / Acknowledgement

Although I am the only named contributor on this project (as of now), I want to thank all the people who have helped with the Architecture of this solution and the devlopment of each piece. Initially, this project came to life from a co-worker of mine (and he had a much cooler name for it), but I have not been given his permission to give him credit yet so he will stay anonymous until then.

And not to mention all the people in BloodHound slack that I pestered for getting feedback on this solution. Thank you!

## Known Limitations / Issues

There are known issues / quirks to Terry. Here are some of the ones I have identified:

* Logging errors will NOT print the stack trace
* No central managment of wildcard Certs
* UFW rules to containers must run both `ufw allow` and `ufw route allow` to allow ufw to manage the docker routes

## What's next?

* Adding a secrets management solution to Terry to allow for dynamic generation of secrets and automatic pushing of secrets to a secure place
