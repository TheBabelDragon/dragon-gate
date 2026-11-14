# Installation

## Development

```bash
git clone https://github.com/TheBabelDragon/dragon-gate.git
cd dragon-gate
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
dragon-gate status
```

## Arch Linux (PKGBUILD)

See `packaging/arch/PKGBUILD`.

```bash
cd packaging/arch
makepkg -si
```

Ordinary inspection commands do **not** require root. Privileged networking capabilities (e.g., interface management, WireGuard) will be declared and opt-in in later versions.
