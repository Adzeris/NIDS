# IoT Integration Notes

NIDS v5 introduces an IoT-aware foundation with two separate modes. They solve different deployment problems and should not be confused.

## 1. Gateway Monitoring Mode

Gateway monitoring runs from the main NIDS GUI/engine on a Linux monitoring machine, VM, bridge, router-like host, or mirrored/SPAN network point.

Relevant file:

- `modules/iot_profile.py`

Purpose:

- Passively observe IoT/LAN devices from network traffic.
- Build a lightweight inventory of seen MAC/IP pairs.
- Alert on scan-like destination-port fanout from a device.
- Keep this mode non-blocking by default so it can be used safely for research and baselining.

Use this when the IoT devices cannot run custom software or when you want one central machine watching the network.

## 2. Endpoint Agent Mode

Endpoint agent mode installs a lightweight agent directly on Linux-based IoT devices.

Relevant files:

- `agent/nids-agent.py`
- `agent/agent_config.json`
- `agent/install-agent.sh`
- `agent/uninstall-agent.sh`
- `agent/systemd/nids-agent.service`

Purpose:

- Run without the PyQt GUI.
- Use only Python standard-library features.
- Monitor local failed-login bursts, outbound port fanout, and high packet-rate behavior.
- Write local JSONL events to `/var/log/nids-agent/events.jsonl`.
- Optionally POST events to a controller URL configured in `/etc/nids-agent/agent_config.json`.

Supported target type:

- Raspberry Pi OS
- Debian/Ubuntu ARM
- Kali ARM
- Generic Linux-based IoT boards with Python 3 and systemd

Not supported as an endpoint target:

- ESP32/Arduino-style microcontrollers
- locked commercial firmware without shell/root access
- non-Linux devices without Python 3

Install on a target device:

```bash
sudo ./agent/install-agent.sh
```

Check status:

```bash
sudo systemctl status nids-agent
```

View logs:

```bash
sudo tail -f /var/log/nids-agent/events.jsonl
```

## Roadmap

- Add a GUI tab for endpoint agent inventory.
- Add a simple controller receiver for agent POST events.
- Add per-device profiles such as camera, printer, sensor, gateway, and unknown IoT device.
- Add signed/shared-token authentication between agents and controller.
