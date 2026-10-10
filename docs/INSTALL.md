# Installation

Tested on Kali Linux (2025.x), everything on one machine: Mininet, Open vSwitch, the Ryu controller, and the Flask dashboard.

**Read this before you start:** Ryu's last release (4.34, 2021) does not run on Python 3.11+. Modern Kali ships Python 3.12/3.13 by default. Installing Ryu "normally" (`pip install ryu`) will fail or silently produce a broken package. The steps below exist specifically to work around that — skipping them will cost you real time rediscovering the same problems.

## 1. Python 3.9 via pyenv

```bash
sudo apt update
sudo apt install -y make build-essential libssl-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev wget curl libncursesw5-dev xz-utils \
  tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev git

curl https://pyenv.run | bash
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.zshrc   # ~/.bashrc if you use bash
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.zshrc
echo 'eval "$(pyenv init -)"' >> ~/.zshrc
source ~/.zshrc

pyenv install 3.9.18
```

## 2. Virtual environment

```bash
~/.pyenv/versions/3.9.18/bin/python3.9 -m venv ~/holo-venv
source ~/holo-venv/bin/activate
pip install --upgrade pip
```

## 3. Ryu itself — the part that actually breaks

`pip install ryu` fails on a modern setuptools (the error looks like `AttributeError: 'types.SimpleNamespace' object has no attribute 'get_script_args'`). The PyPI tarball also has broken version metadata, so even `pip install git+https://.../ryu.git` can silently install a near-empty package reporting version `0.0.0`.

The combination that actually works:

```bash
# Old setuptools that still has the API Ryu's install hooks expect
pip install "setuptools==57.5.0" wheel --no-cache-dir

# Full clone (NOT --depth 1 — pbr needs the git history/tags to
# determine the version correctly)
git clone https://github.com/faucetsdn/ryu.git ~/ryu-src
cd ~/ryu-src
git checkout v4.34

# Classic setup.py install, NOT `pip install .` — PEP 517 build
# isolation breaks pbr's file discovery for this package
python setup.py install
```

Verify: `pip show ryu` should report version `4.34` with a long file list, not `0.0.0` with just a few `dist-info` files.

## 4. Runtime dependencies `setup.py install` doesn't pull in

```bash
pip install --no-cache-dir eventlet==0.30.2 msgpack netaddr "oslo.config" ovs routes tinyrpc webob six
```

`eventlet==0.30.2` specifically — a newer eventlet removes `ALREADY_HANDLED` from `eventlet.wsgi`, which Ryu's WSGI app imports at startup and crashes on.

Verify:
```bash
ryu-manager --version   # should print: ryu-manager 4.34
```

## 5. Mininet + Open vSwitch

```bash
sudo apt install -y mininet openvswitch-switch
sudo service openvswitch-switch start
which ovs-vswitchd   # should resolve
```

## 6. Dashboard dependencies

```bash
cd dashboard
pip install --no-cache-dir -r requirements.txt
```

(`scipy` is required — it's easy to miss if you only remember `scikit-learn`; it's what the online anomaly model's chi-square scoring uses.)

## 7. Running everything (three terminals, same machine)

```bash
# Terminal 1 — controller
source ~/holo-venv/bin/activate
cd controller
export HOLO_FLOOD_PPS_THRESHOLD=15        # tune for your hardware — see note below
export HOLO_SCAN_WINDOW_SECONDS=20
export HOLO_FLOW_IDLE_TIMEOUT=10
ryu-manager --verbose sec_switch.py
# wait for: "Active thresholds: ..." — confirms your env vars actually took effect

# Terminal 2 — dashboard
source ~/holo-venv/bin/activate
cd dashboard
export HOLO_ADMIN_PASSWORD="choose-a-real-password"
python3 app.py
# -> http://127.0.0.1:5000

# Terminal 3 — test topology
sudo mn --topo single,6 --controller=remote,ip=127.0.0.1,port=6653
mininet> pingall    # should be 0% dropped
```

## A note on threshold tuning

The flood/scan thresholds (`FLOOD_PPS_THRESHOLD`, `SCAN_WINDOW_SECONDS`, `SCAN_DISTINCT_DEST_THRESHOLD`, `FLOW_IDLE_TIMEOUT`, `FLOOD_CONSECUTIVE_POLLS_TO_BLOCK`) are all environment-variable-configurable on purpose — *what counts as a flood* depends entirely on how fast your testbed can generate traffic. Running Mininet, the controller, the dashboard, and a Python/Scapy traffic generator all on one resource-constrained VM measurably throttles what Scapy can send (observed as low as ~20 packets/sec where a dedicated machine produced 600-700+). Recalibrate for your actual hardware rather than assuming the defaults are universal; the controller prints the thresholds it's actually running with at startup specifically so this is never ambiguous.

## Common failure modes (seen during development)

- **`sudo mn -c` kills your running controller too**, not just stale Mininet state — it kills anything listening on the OpenFlow port. Run it once before starting the controller, not between test runs.
- **"Unable to contact the remote controller"** at Mininet startup, followed by 100% ping drop — almost always means either the controller isn't actually running, or a prior Mininet session wasn't cleaned up (`sudo mn -c`, then restart the controller too).
- **A `python3 app.py` that "does nothing"** — if it printed `Running on http://127.0.0.1:5000` and the terminal just sits there, that's correct; Flask's dev server blocks the terminal by design. It isn't hung.
- **A `ryu-manager` terminal that goes quiet after "BRICK SecureSwitch" output** — also correct. It's waiting for a switch to connect; no further output is expected until Mininet starts.
