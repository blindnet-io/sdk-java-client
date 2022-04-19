# Blindnet Java SDK

This repository contains Java implementation of Blindnet SDK.

The SDK consists of two submodules. The Core submodule and the Signal submodule.
The implementation of these submodules resides in the packages named same as the submodules.

The project uses Gradle build tool.

# Requirements

```
Java v11+
Gradle v7.3.1+
```

# Building project

In order to build the project run:
```
gradle build
```

In order to run tests:
```
gradle clean test
```

# Using SDK

In order to use the SDK, it is important to note that it is mandatory 
to add the Bouncy Castle Security provider, and that can be done by simply doing:

```
Security.addProvider(new BouncyCastleProvider());
```

## Signal example

The usage example is provided within two classes, both residing in the main package.
The class names are Alice and Bob.
In order to run a simple example, a couple of arguments need to be provided in both classes.
During initialization of the
```
BlindnetSignal
```
class, the database path and user token need to be provided. The database path is the path to
SQLite database of the device, while the token is generated using Blindnet API. Furthermore,
the username must be provided as well, and it has to be the same one as the one used for
token generation.
