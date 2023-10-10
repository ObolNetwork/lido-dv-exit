# lido-dv-exit

`lido-dv-exit` is a program that automatically pre-generates and signs validator voluntary exit messages for a
Charon cluster.

Its primary design intention is to be used in the context of a Charon cluster that is deployed as part of a Lido
operator setup.

## Configuration

`lido-dv-exit` can be configured either through CLI parameters, or environment variables.

It contains a few subcommands:

```
Validator exit tool for Lido

Usage:
  lido-exit-dv [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  mockservers Runs the beacon mock implementation.
  run         Runs lido-dv-exit
  version     Returns lido-dv-exit version information

Flags:
  -h, --help   help for lido-exit-dv

Use "lido-exit-dv [command] --help" for more information about a command.
```

For each subcommand, there are several flags --- for example, `lido-dv-exit run -h` shows:

```
Runs lido-dv-exit

Usage:
  lido-exit-dv run [flags]

Flags:
  -b, --beacon-node-url string      URL pointing to a running ethereum beacon node.
  -c, --charon-runtime-dir string   Charon directory, containing the validator_keys directory and manifest file or lock file.
  -e, --ejector-exit-path string    Filesystem path to store full exit.
      --exit-epoch uint             Epoch to exit validators at. (default 194048)
  -h, --help                        help for run
      --log-color string            Log color; auto, force, disable. (default "auto")
      --log-format string           Log format; console, logfmt or json (default "console")
      --log-level string            Log level; debug, info, warn or error (default "info")
  -o, --obol-api-url string         URL pointing to an obol API instance. (default "https://api.obol.tech")
```

The flags that show default values can be omitted if correct.

## Running the program

To `run`, one must provide:
 - a beacon node (`--beacon-node-url`)
 - a directory in which `lido-dv-exit` will write signed voluntary exits, and where
[`validator-ejector`](https://github.com/lidofinance/validator-ejector) will pick them up (`--ejector-exit-path`)
 - a directory containing Charon's lock file, identity private key and validator shares (`--charon-runtime-dir`)

Optionally one can specify an exit epoch, and an instance of the Obol API to be used for coordination purposes.

One can also run the program with Docker, provided that the volume pointed to by `--ejector-exit-path` is writable.
