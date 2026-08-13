# Contributing

Thanks for taking a look. Issues and pull requests are welcome.

## Setup

Requires Python 3.12+ (the suite is also CI-tested on 3.13). No third-party
packages: the standard library is enough to run the tests.

```bash
git clone https://github.com/dallascrilley/matchbox.git
cd cinderwell
python3 -m unittest discover -s tests -t tests
python3 examples/mock_teardown.py
```

Four skips are expected in a bare checkout (three cloud-init tests without a
YAML parser; one contract test without the `hcloud` CLI). Everything else is
unconditional.

To install the CLI (Homebrew/Debian Python is PEP 668 managed):

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install .
cinderwell --help
```

## The checks CI runs

`.github/workflows/ci.yml` runs, on Ubuntu and macOS, Python 3.12 and 3.13:

```bash
python -m unittest discover -s tests -t tests -v
python examples/mock_teardown.py
```

A separate job installs the package and runs `cinderwell --help` and
`cinderwell doctor`. The test job deliberately does **not** `pip install`
dependencies: if the suite ever needs network or a third-party package, it
stopped being hermetic.

## What a good change looks like

- **Guards stay real.** Teardown and reaper paths must keep exact-ID delete plus
  a fresh provider re-read. Do not add a private reaper path that skips guards.
- **Secrets stay as commands.** Config must not grow fields that hold token
  values. Prefer `*_command` argv lists.
- **Proofs stay executable.** If you change the receipt shape, update
  `examples/mock_teardown.py` and the tests that lock its schema in the same
  change.
- **Brand is cinderwell.** User-facing CLI, console markers, and error text use
  that name — not internal legacy labels.

## Scope

This is a reference extract of one production spine (plan, approve, provision,
lease, reap, destroy, prove). Prefer a focused patch over a multi-cloud
framework.
