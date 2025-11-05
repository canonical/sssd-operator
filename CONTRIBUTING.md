# Contributing

To make contributions to this charm, you'll need a working [development setup](https://juju.is/docs/sdk/dev-setup).

You can create a development environment using `just`:

```shell
just env
source .venv/bin/activate
```

## Testing

This project uses `just` for managing development tasks. There are some pre-configured recipes
that can be used for linting and formatting code when you're preparing contributions to the charm:

```shell
just fmt           # update your code according to linting rules
just lint          # code style
just unit          # unit tests
just integration   # integration tests
```

## Build the charm

Build the charm in this git repository using:

```shell
charmcraft pack
```

<!-- You may want to include any contribution/style guidelines in this document>