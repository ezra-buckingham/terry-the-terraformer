
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

I want to thank all the people who have helped with the Architecture of this solution and the devlopment of each piece. Initially, this project came to life from a co-worker, [WJDigby](https://github.com/WJDigby), and he had a much cooler name for it.

And not to mention all the people in BloodHound slack that I pestered for getting feedback on this solution. Thank you!

## Known Issues

There are known issues to Terry. Here are some of the ones I have identified:

* Logging errors to the log file will won't print the stack trace
* No central managment of wildcard certs (wildcard cert generation likely coming in the future)
* Nebula path required even when not being used
* Need to check for `None` in remote config
* PTR records need to be determined before SMTP will work
  * DigitalOcean will create PTR records from the name of the host, need to make sure name of host is the FQDN

## What's next?

* Adding a secrets management solution to Terry to allow for dynamic generation of secrets and automatic pushing of secrets to a secure place
* Timeout date on infra (auto-destroy)
