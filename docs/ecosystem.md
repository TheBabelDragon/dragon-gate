# Ecosystem Expansion Contracts

Dragon Gate does **not** create mandatory dependencies on sibling repositories.
Integration is via versioned schemas and explicit adapters.

| Project | Role relative to Dragon Gate |
|---------|------------------------------|
| **Aurora** | Autonomous routing and network fabric — owns destination routing |
| **CANtheon** | Hardware / CAN diagnostics — not an assumed IP transport |
| **BabelCodec** | Encoding and canonical interchange — future evidence normalization |
| **REA** | Protocol inspection and reconstruction |
| **TensorGate** | Optional compute and experimentation |
| **Signal Processor** | Acoustic transport experiments |
| **c3-field-swarm** | Physical optical and field-network experiments |

Adapters live under `dragon_gate.aurora` (and future packages) and are activated by configuration, never by hard-coded imports of sibling repos.
