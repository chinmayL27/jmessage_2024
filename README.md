# UPDATE :

## Contribution of Chinmay Lohani towards the parent project.

### Not safe (will update the exploit code soon)

# JMessage Overview

This repository contains code and specifications for the JMessage system.

See the following resources:

- [JMessage Specification](specification.md)
- [How to run the JMessage server locally](running_server.md)

In addition, you will find code for the server and a skeleton of the unfinished Golang client.

## TO EXECUTE

- Terminal 1

```
$ python jmessage_server.py
```

- Terminal 2 (authentic sender)

```
$ go run . --reg --username <sender> --password abc
```

### COPY the payload from terminal

- Terminal 3 (bot to read messages)

```
$ go run . --reg --username <receiver> --password abc
    > bob
```

- Terminal 4 (attacker)

```
$ go run . --reg --username <alica> --password abc
    > attack <sender> receiver <payload>
```
