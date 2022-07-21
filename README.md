# Blindnet Java SDK
<h1 align="center">
  blindnet devkit<br />
  Java Client SDK
</h1>

<p align=center><img src="https://user-images.githubusercontent.com/7578400/163277439-edd00509-1d1b-4565-a0d3-49057ebeb92a.png#gh-light-mode-only" height="80" /></p>
<p align=center><img src="https://user-images.githubusercontent.com/7578400/163549893-117bbd70-b81a-47fd-8e1f-844911e48d68.png#gh-dark-mode-only" height="80" /></p>

<p align="center">
  <strong>{One-Liner: Explain concretely what this project does in one short sentence}</strong>
</p>

<p align="center">
  <a href="https://blindnet.dev"><strong>blindnet.dev</strong></a>
</p>

<p align="center">
  <a href="https://blindnet.dev/docs">Documentation</a>
  &nbsp;•&nbsp;
  <a href="https://github.com/blindnet-io/{project-short-name}/issues">Submit an Issue</a>
  &nbsp;•&nbsp;
  <a href="https://join.slack.com/t/blindnet/shared_invite/zt-1arqlhqt3-A8dPYXLbrnqz1ZKsz6ItOg">Online Chat</a>
  <br>
  <br>
</p>

## About


This is the Java client-side SDK component of blindnet devkit allowing you to:

- encrypt and decrypt data for users,
- and manage user and data encryption keys.

Those functionalities are provided through two submodules:

- Core: this module uses Bouncy Castle library in order to expose API using which a client
is able to perform encrypt/decrypt of data for users and manage users and their encryption keys. The module
is provided through the interface named
```
  Blindnet
```
- Signal: this module uses Signal library in order to expose API using which a client
  is able to perform encrypt/decrypt of data for users and manage users and their encryption keys. The module
  is provided through the interface named
```
  BlindnetSignal
```

## Get Started

:rocket: Check out our [Quick Start Guide](https://blindnet.dev/docs/quickstart) to get started in a snap.

## Installation

This project requires [Java v11+](URL) {...} [Gradle v7.3.1+](URL) {...}

Use Gradle Build Tool to build, install and test the project. To build project run:

```bash
gradle build
```

In order to run tests use:

```bash
gradle clean test
```

## Usage

<!-- FIXME: RESTRUCTURE and REWRITE in plain and correct english, using clear code examples -->

<!-- FIXME: publish the API reference -->

> 📑 The API reference of blindnet devkit Java client SDK is available on [blindnet.dev](https://blindnet.dev/docs/api_reference/[path-to-project}/latest).

### Requirements

In order to use the SDK, it is important to note that it is mandatory 
to add the Bouncy Castle Security provider, and that can be done by simply doing:

```java
Security.addProvider(new BouncyCastleProvider());
```

### Signal example

The usage example is provided within two classes, both residing in the main package.

The class names are Alice and Bob.

In order to run a simple example, a couple of arguments need to be provided in both classes.

During initialization of the `BlindnetSignal` class, the database path and user token need to be provided.
The database path is the path to SQLite database of the device, while the token is generated using Blindnet API.
Furthermore, the username must be provided as well, and it has to be the same one as the one used for token generation.

## Contributing

Contributions of all kinds are always welcome!

If you see a bug or room for improvement in this project in particular, please [open an issue][new-issue] or directly [fork this repository][fork] to submit a Pull Request.

If you have any broader questions or suggestions, just open a simple informal [DevRel Request][request], and we'll make sure to quickly find the best solution for you.

## Community

> All community participation is subject to blindnet’s [Code of Conduct][coc].
Stay up to date with new releases and projects, learn more about how to protect your privacy and that of our users, and share projects and feedback with our team.

- [Join our Slack Workspace][chat] to chat with the blindnet community and team
- Follow us on [Twitter][twitter] to stay up to date with the latest news
- Check out our [Openness Framework][openness] and [Product Management][product] on Github to see how we operate and give us feedback.

## License

The blindnet devkit sdk-java-client is available under [MIT][license] (and [here](https://github.com/blindnet-io/openness-framework/blob/main/docs/decision-records/DR-0001-oss-license.md) is why).

<!-- project's URLs -->
[new-issue]: https://github.com/blindnet-io/sdk-java-client/issues/new/choose
[fork]: https://github.com/blindnet-io/sdk-java-client/fork

<!-- common URLs -->
[devkit]: https://github.com/blindnet-io/blindnet.dev
[openness]: https://github.com/blindnet-io/openness-framework
[product]: https://github.com/blindnet-io/product-management
[request]: https://github.com/blindnet-io/devrel-management/issues/new?assignees=noelmace&labels=request%2Ctriage&template=request.yml&title=%5BRequest%5D%3A+
[chat]: https://join.slack.com/t/blindnet/shared_invite/zt-1arqlhqt3-A8dPYXLbrnqz1ZKsz6ItOg
[twitter]: https://twitter.com/blindnet_io
[docs]: https://blindnet.dev/docs
[changelog]: CHANGELOG.md
[license]: LICENSE
[coc]: https://github.com/blindnet-io/openness-framework/blob/main/CODE_OF_CONDUCT.md
