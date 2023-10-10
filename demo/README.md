# lido-dv-exit demo

This directory contains a few demo scripts which simulate a Lido validator being exited by means of `lido-dv-exit`.

The `run.sh` script is the main star of the show: it sets up a mock validator API, mock execution client with Lido
smart contracts mirrored off mainnet, 4 [`validator-ejector`](https://github.com/lidofinance/validator-ejector) and `lido-dv-exit` instances.

Caveat on `validator-ejector`: the image is tagged with `local` because there's no official image that targets `arm64`:
YMMV.

Run the script, and observe its output: you'll be required to press ENTER at some stage, for the sake of interactivity.

To watch the exit being handled: log onto a serial of any of the `validator-ejector` Docker container with:

```shell
docker logs -f ejector_node0
```
