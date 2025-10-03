![Iamshield](https://github.com/iamshield/iamshield-misc/blob/main/logo/logo.svg)

![GitHub Release](https://img.shields.io/github/v/release/iamshield/iamshield?label=latest%20release)
[![OpenSSF Best Practices](https://bestpractices.coreinfrastructure.org/projects/6818/badge)](https://bestpractices.coreinfrastructure.org/projects/6818)
[![CLOMonitor](https://img.shields.io/endpoint?url=https://clomonitor.io/api/projects/cncf/iamshield/badge)](https://clomonitor.io/projects/cncf/iamshield)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/iamshield/iamshield/badge)](https://securityscorecards.dev/viewer/?uri=github.com/iamshield/iamshield)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/iamshield-operator)](https://artifacthub.io/packages/olm/community-operators/iamshield-operator)
![GitHub Repo stars](https://img.shields.io/github/stars/iamshield/iamshield?style=flat)
![GitHub commit activity](https://img.shields.io/github/commit-activity/m/iamshield/iamshield)
[![Translation status](https://hosted.weblate.org/widget/iamshield/svg-badge.svg)](docs/translation.md)

# Open Source Identity and Access Management

Add authentication to applications and secure services with minimum effort. No need to deal with storing users or authenticating users.

Iamshield provides user federation, strong authentication, user management, fine-grained authorization, and more.


## Help and Documentation

* [Documentation](https://www.iamshield.org/documentation.html)
* [User Mailing List](https://groups.google.com/d/forum/iamshield-user) - Mailing list for help and general questions about Iamshield
* Join [#iamshield](https://cloud-native.slack.com/archives/C056HC17KK9) for general questions, or [#iamshield-dev](https://cloud-native.slack.com/archives/C056XU905S6) on Slack for design and development discussions, by creating an account at [https://slack.cncf.io/](https://slack.cncf.io/).


## Reporting Security Vulnerabilities

If you have found a security vulnerability, please look at the [instructions on how to properly report it](https://github.com/iamshield/iamshield/security/policy).


## Reporting an issue

If you believe you have discovered a defect in Iamshield, please open [an issue](https://github.com/iamshield/iamshield/issues).
Please remember to provide a good summary, description as well as steps to reproduce the issue.


## Getting started

To run Iamshield, download the distribution from our [website](https://www.iamshield.org/downloads.html). Unzip and run:

    bin/kc.[sh|bat] start-dev

Alternatively, you can use the Docker image by running:

    docker run quay.io/iamshield/iamshield start-dev
    
For more details refer to the [Iamshield Documentation](https://www.iamshield.org/documentation.html).


## Building from Source

To build from source, refer to the [building and working with the code base](docs/building.md) guide.


### Testing

To run tests, refer to the [running tests](docs/tests.md) guide.


### Writing Tests

To write tests, refer to the [writing tests](docs/tests-development.md) guide.


## Contributing

Before contributing to Iamshield, please read our [contributing guidelines](CONTRIBUTING.md). Participation in the Iamshield project is governed by the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md).

Joining a [community meeting](https://www.iamshield.org/community) is a great way to get involved and help shape the future of Iamshield.

## Other Iamshield Projects

* [Iamshield](https://github.com/iamshield/iamshield) - Iamshield Server and Java adapters
* [Iamshield QuickStarts](https://github.com/iamshield/iamshield-quickstarts) - QuickStarts for getting started with Iamshield
* [Iamshield Node.js Connect](https://github.com/iamshield/iamshield-nodejs-connect) - Node.js adapter for Iamshield


## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)
