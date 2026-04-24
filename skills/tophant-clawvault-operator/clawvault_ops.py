#!/usr/bin/env python3
"""
ClawVault Operations - Standalone Skill for OpenClaw

Operates ClawVault services, configuration, vault presets, scanning,
and local filesystem security scans. Complements the tophant-clawvault-installer
skill (install/health/generate-rule/test/uninstall).

Usage:
    python clawvault_ops.py start --mode interactive
    python clawvault_ops.py stop
    python clawvault_ops.py status
    python clawvault_ops.py scan "sk-proj-abc123"
    python clawvault_ops.py scan-file /path/to/.env
    python clawvault_ops.py config-show
    python clawvault_ops.py config-get guard.mode
    python clawvault_ops.py config-set guard.mode strict
    python clawvault_ops.py vault-list
    python clawvault_ops.py vault-show full-lockdown
    python clawvault_ops.py vault-apply full-lockdown
    python clawvault_ops.py vault-create "My Preset" --id my-preset
    python clawvault_ops.py vault-update my-preset --name "Renamed"
    python clawvault_ops.py vault-delete my-preset
    python clawvault_ops.py vault-active
    python clawvault_ops.py local-scan --type credential
    python clawvault_ops.py scan-schedule-add --cron "0 2 * * *"
    python clawvault_ops.py scan-schedule-list
    python clawvault_ops.py scan-schedule-remove <id>
    python clawvault_ops.py scan-history
    python clawvault_ops.py agent-list
    python clawvault_ops.py agent-set "OpenClaw" --guard-mode permissive --no-prompt-injection
    python clawvault_ops.py agent-remove <agent_id>

For OpenClaw integration:
    openclaw skill run tophant-clawvault-operator start --mode interactive
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Optional


class ClawVaultOps:
    """Standalone ClawVault operations tool for OpenClaw agents."""

    def __init__(
        self,
        dashboard_host: str = "127.0.0.1",
        dashboard_port: int = 8766,
    ):
        self.config_dir = Path.home() / ".ClawVault"
        self.config_path = self.config_dir / "config.yaml"
        self.dashboard_host = dashboard_host
        self.dashboard_port = dashboard_port

    # ── Helpers ────────────────────────────────────────────────────

    def _probe_port(self, host: str, port: int, timeout: float = 1.0) -> bool:
        """Test whether a TCP port is accepting connections."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _load_config(self, config_path: Optional[str] = None) -> dict:
        """Load YAML config from disk."""
        import yaml

        path = Path(config_path) if config_path else self.config_path
        if not path.exists():
            return {}
        with open(path) as f:
            return yaml.safe_load(f) or {}

    def _save_config(self, config: dict, config_path: Optional[str] = None) -> str:
        """Save YAML config to disk."""
        import yaml

        # Strip config-show output wrapper if present
        if "success" in config and "config" in config and "config_path" in config:
            config = config["config"]

        path = Path(config_path) if config_path else self.config_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w") as f:
            yaml.dump(config, f, default_flow_style=False, allow_unicode=True, sort_keys=False)
        return str(path)

    def _parse_value(self, value: str) -> Any:
        """Parse a string value to bool/int/float/string."""
        if value.lower() == "true":
            return True
        if value.lower() == "false":
            return False
        try:
            return int(value)
        except ValueError:
            pass
        try:
            return float(value)
        except ValueError:
            pass
        return value

    def _deep_merge(self, base: dict, update: dict) -> None:
        """Deep merge update into base dict."""
        for key, val in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(val, dict):
                self._deep_merge(base[key], val)
            else:
                base[key] = val

    def _api_request(
        self,
        method: str,
        path: str,
        json_body: Optional[dict] = None,
        timeout: float = 10.0,
    ) -> tuple[bool, Optional[dict]]:
        """Call dashboard API. Returns (api_used, response_dict).

        If dashboard is not running or request fails, returns (False, None)
        so the caller can fall back to file-based logic.
        Uses urllib (stdlib) to avoid external dependency on 'requests'.
        """
        if not self._probe_port(self.dashboard_host, self.dashboard_port):
            return False, None
        try:
            import json as _json
            from urllib.request import Request, urlopen
            from urllib.error import URLError, HTTPError

            url = f"http://{self.dashboard_host}:{self.dashboard_port}{path}"
            body_bytes = _json.dumps(json_body).encode("utf-8") if json_body is not None else None
            req = Request(url, data=body_bytes, method=method)
            req.add_header("Content-Type", "application/json")
            try:
                with urlopen(req, timeout=timeout) as resp:
                    raw = resp.read().decode("utf-8")
                    try:
                        data = _json.loads(raw)
                    except ValueError:
                        data = {"raw": raw}
                    return True, data
            except HTTPError as e:
                raw = e.read().decode("utf-8")
                try:
                    data = _json.loads(raw)
                except ValueError:
                    data = {"raw": raw}
                return True, {
                    "success": False,
                    "error": data.get("detail", data.get("error", raw)),
                    "status_code": e.code,
                }
        except (URLError, OSError):
            return False, None

    # ── Group A: Service Lifecycle ─────────────────────────────────

    def start(
        self,
        port: int = 8765,
        dashboard_port: int = 8766,
        dashboard_host: str = "127.0.0.1",
        mode: Optional[str] = None,
        no_dashboard: bool = False,
    ) -> dict:
        """Start ClawVault proxy and dashboard services."""
        # Check if already running
        if self._probe_port("127.0.0.1", port):
            return {
                "success": False,
                "error": f"Port {port} already in use (proxy may be running)",
            }

        cmd = [sys.executable, "-m", "claw_vault", "start", "--port", str(port)]
        cmd.extend(["--dashboard-port", str(dashboard_port)])
        cmd.extend(["--dashboard-host", dashboard_host])
        if mode:
            cmd.extend(["--mode", mode])
        if no_dashboard:
            cmd.append("--no-dashboard")

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except Exception as e:
            return {"success": False, "error": f"Failed to start: {e}"}

        # Wait for services to come up
        for _ in range(10):
            time.sleep(0.5)
            proxy_up = self._probe_port("127.0.0.1", port)
            dashboard_up = no_dashboard or self._probe_port(dashboard_host, dashboard_port)
            if proxy_up and dashboard_up:
                return {
                    "success": True,
                    "pid": process.pid,
                    "proxy": {"port": port, "running": True},
                    "dashboard": {
                        "port": dashboard_port,
                        "host": dashboard_host,
                        "running": not no_dashboard and dashboard_up,
                    },
                    "mode": mode or "default",
                }

        # Check if process died
        if process.poll() is not None:
            stderr = process.stderr.read().decode() if process.stderr else ""
            return {
                "success": False,
                "error": f"Process exited with code {process.returncode}",
                "stderr": stderr[:500],
            }

        return {
            "success": True,
            "pid": process.pid,
            "proxy": {"port": port, "running": self._probe_port("127.0.0.1", port)},
            "dashboard": {
                "port": dashboard_port,
                "running": self._probe_port(dashboard_host, dashboard_port),
            },
            "warning": "Services may still be starting up",
        }

    def stop(self, force: bool = False) -> dict:
        """Stop running ClawVault services."""
        pids = []

        # Find clawvault processes
        try:
            result = subprocess.run(
                ["pgrep", "-f", "clawvault start"],
                capture_output=True,
                text=True,
            )
            pids = [int(p.strip()) for p in result.stdout.strip().split("\n") if p.strip()]
        except Exception:
            pass

        # Also check for claw_vault module processes
        if not pids:
            try:
                result = subprocess.run(
                    ["pgrep", "-f", "claw_vault"],
                    capture_output=True,
                    text=True,
                )
                pids = [int(p.strip()) for p in result.stdout.strip().split("\n") if p.strip()]
            except Exception:
                pass

        if not pids:
            return {"success": True, "message": "No running ClawVault processes found"}

        # Graceful shutdown (SIGTERM)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError):
                pass

        time.sleep(3)

        # Check which are still running
        still_running = []
        for pid in pids:
            try:
                os.kill(pid, 0)
                still_running.append(pid)
            except (ProcessLookupError, PermissionError):
                pass

        if still_running and force:
            for pid in still_running:
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
            time.sleep(1)
            still_running = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    still_running.append(pid)
                except (ProcessLookupError, PermissionError):
                    pass

        stopped = [p for p in pids if p not in still_running]

        return {
            "success": len(still_running) == 0,
            "stopped_pids": stopped,
            "still_running": still_running,
            "message": (
                "All processes stopped"
                if not still_running
                else f"Processes still running: {still_running}. Use --force to kill."
            ),
        }

    def check_status(
        self,
        proxy_port: int = 8765,
        dashboard_port: int = 8766,
        dashboard_host: str = "127.0.0.1",
    ) -> dict:
        """Check if ClawVault proxy and dashboard are running."""
        proxy_running = self._probe_port("127.0.0.1", proxy_port)
        dashboard_running = self._probe_port(dashboard_host, dashboard_port)

        return {
            "success": True,
            "proxy": {"port": proxy_port, "running": proxy_running},
            "dashboard": {
                "port": dashboard_port,
                "host": dashboard_host,
                "running": dashboard_running,
            },
            "active": proxy_running or dashboard_running,
        }

    # ── Group B: Configuration ─────────────────────────────────────

    def config_show(self, config_path: Optional[str] = None) -> dict:
        """Show current ClawVault configuration."""
        path = Path(config_path) if config_path else self.config_path
        if not path.exists():
            return {
                "success": False,
                "error": f"Config file not found: {path}",
                "hint": "Run 'clawvault config init' to create one",
            }

        config = self._load_config(config_path)
        return {
            "success": True,
            "config_path": str(path),
            "config": config,
        }

    def config_get(self, key: str, config_path: Optional[str] = None) -> dict:
        """Get a configuration value by dotted key."""
        parts = key.split(".")
        if len(parts) < 2:
            return {"success": False, "error": "Key must be dotted, e.g. 'guard.mode'"}

        config = self._load_config(config_path)
        section_name = parts[0]

        if section_name not in config:
            return {
                "success": False,
                "error": f"Unknown section '{section_name}'",
                "available": list(config.keys()),
            }

        section = config[section_name]
        field = parts[1]

        if not isinstance(section, dict) or field not in section:
            available = list(section.keys()) if isinstance(section, dict) else []
            return {
                "success": False,
                "error": f"Unknown field '{field}' in section '{section_name}'",
                "available": available,
            }

        return {
            "success": True,
            "key": key,
            "value": section[field],
        }

    def config_set(self, key: str, value: str, config_path: Optional[str] = None) -> dict:
        """Set a configuration value by dotted key."""
        parts = key.split(".")
        if len(parts) < 2:
            return {"success": False, "error": "Key must be dotted, e.g. 'guard.mode'"}

        config = self._load_config(config_path)
        section_name = parts[0]
        field = parts[1]

        if section_name not in config:
            config[section_name] = {}

        section = config[section_name]
        if not isinstance(section, dict):
            return {"success": False, "error": f"Section '{section_name}' is not a dict"}

        old_value = section.get(field)
        parsed_value = self._parse_value(value)
        section[field] = parsed_value

        # Try API hot-update first — if available, the dashboard handles
        # runtime update + preset sync + config persistence.
        api_used = self._try_config_api_update(section_name, config.get(section_name, {}))
        if api_used:
            import time
            time.sleep(0.15)
            final_config = self._load_config(config_path)
            result: dict[str, Any] = {
                "success": True,
                "key": key,
                "old_value": old_value,
                "new_value": parsed_value,
                "source": "api",
            }
            final_active = final_config.get("vaults", {}).get("active_preset_id")
            if final_active:
                for p in final_config.get("vaults", {}).get("presets", []):
                    if p.get("id") == final_active and not p.get("builtin"):
                        result["preset_sync"] = {
                            "action": "synced_by_dashboard",
                            "preset_id": final_active,
                            "preset_name": p.get("name", ""),
                        }
                        break
        else:
            # File-only fallback: sync preset ourselves
            sync_info = self._sync_active_preset(config, section_name)
            saved_path = self._save_config(config, config_path)
            result = {
                "success": True,
                "key": key,
                "old_value": old_value,
                "new_value": parsed_value,
                "config_path": saved_path,
                "source": "file",
                "warning": "Restart ClawVault for changes to take effect",
            }
            if sync_info:
                result["preset_sync"] = sync_info
        return result

    # API endpoint mapping for config sections that support hot-update
    _CONFIG_API_MAP: dict[str, str] = {
        "file_monitor": "/api/config/file-monitor",
        "guard": "/api/config/guard",
        "detection": "/api/config/detection",
    }

    # Config sections that exist in vault preset snapshots
    _PRESET_SNAPSHOT_SECTIONS = {"detection", "guard", "file_monitor", "rules"}

    def _try_config_api_update(self, section_name: str, section_data: dict) -> bool:
        """Try to hot-update a config section via dashboard API.

        Returns True if API was used, False if not available or not supported.
        """
        api_path = self._CONFIG_API_MAP.get(section_name)
        if not api_path:
            return False
        api_used, resp = self._api_request("POST", api_path, json_body=section_data)
        return api_used and resp is not None and resp.get("status_code") is None

    def _sync_active_preset(self, config: dict, section_name: str) -> dict:
        """Sync a config change into the active vault preset, matching Web UI logic.

        - Builtin active preset: create a custom copy "Name (Custom)" with updated
          config snapshot, and set it as the new active preset.
        - Custom active preset: update the snapshot directly.
        - No active preset: no-op.

        Returns a dict with sync details (empty if no sync happened).
        """
        if section_name not in self._PRESET_SNAPSHOT_SECTIONS:
            return {}

        vaults = config.get("vaults", {})
        active_id = vaults.get("active_preset_id")
        if not active_id:
            return {}

        presets = vaults.get("presets", [])
        active_preset = None
        for preset in presets:
            if preset.get("id") == active_id:
                active_preset = preset
                break
        if not active_preset:
            return {}

        # Build full snapshot from current config
        snapshot_sections = {
            "detection": dict(config.get("detection", {})),
            "guard": dict(config.get("guard", {})),
            "file_monitor": dict(config.get("file_monitor", {})),
            "rules": list(config.get("rules", [])),
        }

        if active_preset.get("builtin"):
            # Builtin preset — create a custom copy (same as Web UI)
            import uuid

            base_name = active_preset.get("name", "Preset")
            copy_name = f"{base_name} (Custom)"
            # Check if a custom copy with this name already exists
            existing_copy = None
            for p in presets:
                if p.get("name") == copy_name and not p.get("builtin"):
                    existing_copy = p
                    break

            if existing_copy:
                # Update the existing custom copy
                for sec, data in snapshot_sections.items():
                    existing_copy[sec] = data
                vaults["active_preset_id"] = existing_copy["id"]
                return {"action": "updated_copy", "preset_id": existing_copy["id"], "preset_name": copy_name}
            else:
                # Create a new custom copy
                new_id = str(uuid.uuid4())
                new_preset = {
                    "id": new_id,
                    "name": copy_name,
                    "description": active_preset.get("description", ""),
                    "icon": active_preset.get("icon", "\U0001f512"),
                    "builtin": False,
                    "created_at": "",
                    **snapshot_sections,
                }
                presets.append(new_preset)
                vaults["active_preset_id"] = new_id
                return {"action": "created_copy", "preset_id": new_id, "preset_name": copy_name}
        else:
            # Custom preset — update snapshot directly
            for sec, data in snapshot_sections.items():
                active_preset[sec] = data
            return {"action": "updated", "preset_id": active_id}

    def config_append(self, key: str, value: str, config_path: Optional[str] = None) -> dict:
        """Append a value to a list configuration field."""
        parts = key.split(".")
        if len(parts) < 2:
            return {"success": False, "error": "Key must be dotted, e.g. 'file_monitor.watch_paths'"}

        config = self._load_config(config_path)
        section_name = parts[0]
        field = parts[1]

        if section_name not in config:
            config[section_name] = {}

        section = config[section_name]
        if not isinstance(section, dict):
            return {"success": False, "error": f"Section '{section_name}' is not a dict"}

        current = section.get(field)
        if current is None:
            current = []
            section[field] = current
        elif not isinstance(current, list):
            return {
                "success": False,
                "error": f"Field '{field}' in section '{section_name}' is not a list (type: {type(current).__name__})",
                "hint": "Use config-set for scalar values",
            }

        parsed_value = self._parse_value(value)
        if parsed_value in current:
            return {
                "success": True,
                "already_exists": True,
                "key": key,
                "value": parsed_value,
                "current_list": current,
            }

        current.append(parsed_value)

        # Try API hot-update first — if available, the dashboard handles
        # runtime update + preset sync + config persistence.
        api_used = self._try_config_api_update(section_name, config.get(section_name, {}))
        if api_used:
            import time
            time.sleep(0.15)  # wait for dashboard _persist_config
            final_config = self._load_config(config_path)
            result: dict[str, Any] = {
                "success": True,
                "key": key,
                "added": parsed_value,
                "current_list": final_config.get(section_name, {}).get(field, current),
                "source": "api",
                "hot_updated": True,
            }
            # Report preset sync from dashboard's changes
            final_active = final_config.get("vaults", {}).get("active_preset_id")
            if final_active:
                for p in final_config.get("vaults", {}).get("presets", []):
                    if p.get("id") == final_active and not p.get("builtin"):
                        result["preset_sync"] = {
                            "action": "synced_by_dashboard",
                            "preset_id": final_active,
                            "preset_name": p.get("name", ""),
                        }
                        break
        else:
            # File-only fallback: sync preset ourselves
            sync_info = self._sync_active_preset(config, section_name)
            saved_path = self._save_config(config, config_path)
            result = {
                "success": True,
                "key": key,
                "added": parsed_value,
                "current_list": current,
                "config_path": saved_path,
                "source": "file",
                "warning": "Restart ClawVault for changes to take effect",
            }
            if sync_info:
                result["preset_sync"] = sync_info
        return result

    def config_remove(self, key: str, value: str, config_path: Optional[str] = None) -> dict:
        """Remove a value from a list configuration field."""
        parts = key.split(".")
        if len(parts) < 2:
            return {"success": False, "error": "Key must be dotted, e.g. 'file_monitor.watch_paths'"}

        config = self._load_config(config_path)
        section_name = parts[0]
        field = parts[1]

        section = config.get(section_name)
        if not isinstance(section, dict):
            return {"success": False, "error": f"Section '{section_name}' not found"}

        current = section.get(field)
        if not isinstance(current, list):
            return {
                "success": False,
                "error": f"Field '{field}' in section '{section_name}' is not a list",
                "hint": "Use config-set for scalar values",
            }

        parsed_value = self._parse_value(value)
        if parsed_value not in current:
            return {
                "success": False,
                "error": f"Value '{parsed_value}' not found in {key}",
                "current_list": current,
            }

        current.remove(parsed_value)

        # Try API hot-update first — if available, the dashboard handles
        # runtime update + preset sync + config persistence.
        api_used = self._try_config_api_update(section_name, config.get(section_name, {}))
        if api_used:
            import time
            time.sleep(0.15)
            final_config = self._load_config(config_path)
            result: dict[str, Any] = {
                "success": True,
                "key": key,
                "removed": parsed_value,
                "current_list": final_config.get(section_name, {}).get(field, current),
                "source": "api",
                "hot_updated": True,
            }
            final_active = final_config.get("vaults", {}).get("active_preset_id")
            if final_active:
                for p in final_config.get("vaults", {}).get("presets", []):
                    if p.get("id") == final_active and not p.get("builtin"):
                        result["preset_sync"] = {
                            "action": "synced_by_dashboard",
                            "preset_id": final_active,
                            "preset_name": p.get("name", ""),
                        }
                        break
        else:
            # File-only fallback: sync preset ourselves
            sync_info = self._sync_active_preset(config, section_name)
            saved_path = self._save_config(config, config_path)
            result = {
                "success": True,
                "key": key,
                "removed": parsed_value,
                "current_list": current,
                "config_path": saved_path,
                "source": "file",
                "warning": "Restart ClawVault for changes to take effect",
            }
            if sync_info:
                result["preset_sync"] = sync_info
        return result

    # ── Group C: Vault Presets ─────────────────────────────────────

    def vault_list(self, config_path: Optional[str] = None) -> dict:
        """List all vault presets."""
        config = self._load_config(config_path)
        vaults = config.get("vaults", {})
        presets = vaults.get("presets", [])

        if not presets:
            return {"success": True, "presets": [], "count": 0}

        summary = []
        for p in presets:
            guard_mode = p.get("guard", {}).get("mode", "?")
            summary.append({
                "id": p.get("id", "?"),
                "name": p.get("name", "?"),
                "icon": p.get("icon", ""),
                "description": p.get("description", ""),
                "guard_mode": guard_mode,
                "builtin": p.get("builtin", False),
            })

        return {"success": True, "presets": summary, "count": len(summary)}

    def vault_show(self, preset_id: str, config_path: Optional[str] = None) -> dict:
        """Show detailed configuration of a vault preset."""
        config = self._load_config(config_path)
        presets = config.get("vaults", {}).get("presets", [])

        for p in presets:
            if p.get("id") == preset_id:
                return {
                    "success": True,
                    "preset": {
                        "id": p.get("id"),
                        "name": p.get("name"),
                        "icon": p.get("icon"),
                        "description": p.get("description"),
                        "detection": p.get("detection", {}),
                        "guard": p.get("guard", {}),
                        "file_monitor": p.get("file_monitor", {}),
                        "rules": p.get("rules", []),
                    },
                }

        available = [p.get("id") for p in presets]
        return {
            "success": False,
            "error": f"Preset '{preset_id}' not found",
            "available": available,
        }

    def vault_apply(self, preset_id: str, config_path: Optional[str] = None) -> dict:
        """Apply a vault preset to the active configuration.

        If the dashboard is running, uses the API for runtime hot-patching.
        Otherwise falls back to file-based config update.
        """
        # Try API first (gets runtime hot-patching for free)
        api_used, api_resp = self._api_request(
            "POST", f"/api/vaults/presets/{preset_id}/apply"
        )
        if api_used:
            if api_resp and api_resp.get("success") is not False:
                return {
                    "success": True,
                    "preset_id": preset_id,
                    "preset_name": api_resp.get("preset_name", ""),
                    "guard_mode": api_resp.get("guard_mode", "?"),
                    "source": "api",
                }
            return api_resp or {"success": False, "error": "Empty API response"}

        # File fallback
        config = self._load_config(config_path)
        presets = config.get("vaults", {}).get("presets", [])

        preset = None
        for p in presets:
            if p.get("id") == preset_id:
                preset = p
                break

        if not preset:
            available = [p.get("id") for p in presets]
            return {
                "success": False,
                "error": f"Preset '{preset_id}' not found",
                "available": available,
            }

        # Apply detection settings
        if "detection" in preset and isinstance(preset["detection"], dict):
            if "detection" not in config:
                config["detection"] = {}
            self._deep_merge(config["detection"], preset["detection"])

        # Apply guard settings
        if "guard" in preset and isinstance(preset["guard"], dict):
            if "guard" not in config:
                config["guard"] = {}
            self._deep_merge(config["guard"], preset["guard"])

        # Apply file_monitor settings
        if "file_monitor" in preset and isinstance(preset["file_monitor"], dict):
            if "file_monitor" not in config:
                config["file_monitor"] = {}
            self._deep_merge(config["file_monitor"], preset["file_monitor"])

        # Apply rules
        if "rules" in preset:
            config["rules"] = list(preset["rules"])

        # Track active preset
        config.setdefault("vaults", {})["active_preset_id"] = preset_id

        saved_path = self._save_config(config, config_path)

        return {
            "success": True,
            "preset_id": preset_id,
            "preset_name": preset.get("name", ""),
            "guard_mode": config.get("guard", {}).get("mode", "?"),
            "config_path": saved_path,
            "source": "file",
            "warning": "Restart ClawVault for changes to take effect",
        }

    def vault_create(
        self,
        name: str,
        description: str = "",
        icon: str = "\U0001f512",
        preset_id: Optional[str] = None,
        config_path: Optional[str] = None,
    ) -> dict:
        """Create a custom vault preset from the current configuration."""
        import uuid
        from datetime import datetime, timezone

        pid = preset_id or f"custom-{uuid.uuid4().hex[:8]}"

        # Try API first
        api_used, api_resp = self._api_request(
            "POST",
            "/api/vaults/presets",
            json_body={"name": name, "description": description, "icon": icon, "id": pid},
        )
        if api_used:
            if api_resp and api_resp.get("success") is not False:
                api_resp["success"] = True
                api_resp["source"] = "api"
            return api_resp or {"success": False, "error": "Empty API response"}

        # File fallback: snapshot current config as a new preset
        config = self._load_config(config_path)
        vaults = config.setdefault("vaults", {})
        presets = vaults.setdefault("presets", [])

        # Check for duplicate ID
        for p in presets:
            if p.get("id") == pid:
                return {
                    "success": False,
                    "error": f"Preset ID '{pid}' already exists",
                    "available": [p.get("id") for p in presets],
                }

        preset = {
            "id": pid,
            "name": name,
            "description": description,
            "icon": icon,
            "builtin": False,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "detection": dict(config.get("detection", {})),
            "guard": dict(config.get("guard", {})),
            "file_monitor": dict(config.get("file_monitor", {})),
            "rules": list(config.get("rules", [])),
        }
        presets.append(preset)
        saved_path = self._save_config(config, config_path)

        return {
            "success": True,
            "preset_id": pid,
            "preset_name": name,
            "config_path": saved_path,
            "source": "file",
        }

    def vault_update(
        self,
        preset_id: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        icon: Optional[str] = None,
        from_current: bool = False,
        config_path: Optional[str] = None,
    ) -> dict:
        """Update a custom vault preset's metadata or re-snapshot config."""
        # Build update body
        body: dict[str, Any] = {}
        if name is not None:
            body["name"] = name
        if description is not None:
            body["description"] = description
        if icon is not None:
            body["icon"] = icon

        # Try API first
        if body or from_current:
            api_used, api_resp = self._api_request(
                "PUT",
                f"/api/vaults/presets/{preset_id}",
                json_body=body if not from_current else None,
            )
            if api_used:
                if api_resp and api_resp.get("success") is not False:
                    api_resp["success"] = True
                    api_resp["source"] = "api"
                return api_resp or {"success": False, "error": "Empty API response"}

        # File fallback
        config = self._load_config(config_path)
        presets = config.get("vaults", {}).get("presets", [])

        preset = None
        for p in presets:
            if p.get("id") == preset_id:
                preset = p
                break

        if not preset:
            return {
                "success": False,
                "error": f"Preset '{preset_id}' not found",
                "available": [p.get("id") for p in presets],
            }

        if preset.get("builtin"):
            return {"success": False, "error": "Cannot modify builtin presets"}

        updated_fields = []
        if name is not None:
            preset["name"] = name
            updated_fields.append("name")
        if description is not None:
            preset["description"] = description
            updated_fields.append("description")
        if icon is not None:
            preset["icon"] = icon
            updated_fields.append("icon")

        if from_current:
            preset["detection"] = dict(config.get("detection", {}))
            preset["guard"] = dict(config.get("guard", {}))
            preset["file_monitor"] = dict(config.get("file_monitor", {}))
            preset["rules"] = list(config.get("rules", []))
            updated_fields.extend(["detection", "guard", "file_monitor", "rules"])

        if not updated_fields:
            return {"success": False, "error": "No fields to update"}

        saved_path = self._save_config(config, config_path)

        return {
            "success": True,
            "preset_id": preset_id,
            "updated_fields": updated_fields,
            "config_path": saved_path,
            "source": "file",
        }

    def vault_delete(self, preset_id: str, config_path: Optional[str] = None) -> dict:
        """Delete a custom vault preset."""
        # Try API first
        api_used, api_resp = self._api_request(
            "DELETE", f"/api/vaults/presets/{preset_id}"
        )
        if api_used:
            if api_resp and api_resp.get("success") is not False:
                api_resp["success"] = True
                api_resp["source"] = "api"
            return api_resp or {"success": False, "error": "Empty API response"}

        # File fallback
        config = self._load_config(config_path)
        vaults = config.get("vaults", {})
        presets = vaults.get("presets", [])

        target = None
        for p in presets:
            if p.get("id") == preset_id:
                target = p
                break

        if not target:
            return {
                "success": False,
                "error": f"Preset '{preset_id}' not found",
                "available": [p.get("id") for p in presets],
            }

        if target.get("builtin"):
            return {"success": False, "error": "Cannot delete builtin presets"}

        presets.remove(target)

        # Clear active_preset_id if deleting the active preset
        if vaults.get("active_preset_id") == preset_id:
            vaults["active_preset_id"] = None

        saved_path = self._save_config(config, config_path)

        return {
            "success": True,
            "deleted": preset_id,
            "config_path": saved_path,
            "source": "file",
        }

    def vault_active(self, config_path: Optional[str] = None) -> dict:
        """Show which vault preset is currently active."""
        # Try API first (has inference fallback)
        api_used, api_resp = self._api_request("GET", "/api/vaults/active")
        if api_used and api_resp:
            return {
                "success": True,
                "active_preset_id": api_resp.get("active_preset_id"),
                "source": "api",
            }

        # File fallback
        config = self._load_config(config_path)
        active_id = config.get("vaults", {}).get("active_preset_id")

        return {
            "success": True,
            "active_preset_id": active_id,
            "source": "file",
        }

    # ── Group D: Scanning ──────────────────────────────────────────

    def scan_text(self, text: str) -> dict:
        """Scan text for sensitive data, dangerous commands, and prompt injection."""
        try:
            from claw_vault.detector.engine import DetectionEngine

            engine = DetectionEngine()
            result = engine.scan_full(text)

            findings = []
            for s in result.sensitive:
                findings.append({
                    "type": "sensitive",
                    "description": s.description,
                    "masked_value": s.masked_value,
                    "risk_score": s.risk_score,
                })
            for c in result.commands:
                findings.append({
                    "type": "command",
                    "reason": c.reason,
                    "command": c.command[:100],
                    "risk_score": c.risk_score,
                })
            for i in result.injections:
                findings.append({
                    "type": "injection",
                    "description": i.description,
                    "risk_score": i.risk_score,
                })

            return {
                "success": True,
                "has_threats": result.has_threats,
                "threat_level": result.threat_level.value,
                "max_risk_score": result.max_risk_score,
                "findings": findings,
            }

        except ImportError:
            # Fallback: use CLI subprocess
            return self._scan_via_cli(text)

    def _scan_via_cli(self, text: str) -> dict:
        """Fallback scan using clawvault CLI."""
        try:
            result = subprocess.run(
                [sys.executable, "-m", "claw_vault", "scan", text],
                capture_output=True,
                text=True,
                timeout=30,
            )
            return {
                "success": True,
                "has_threats": result.returncode != 0 or "Threat Level" in result.stdout,
                "output": result.stdout[:2000],
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def scan_file(self, file_path: str) -> dict:
        """Scan a file for sensitive data."""
        path = Path(file_path)
        if not path.exists():
            return {"success": False, "error": f"File not found: {file_path}"}
        if not path.is_file():
            return {"success": False, "error": f"Not a file: {file_path}"}

        size = path.stat().st_size
        if size > 5 * 1024 * 1024:
            return {"success": False, "error": f"File too large: {size} bytes (max 5MB)"}

        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return {"success": False, "error": f"Failed to read file: {e}"}

        result = self.scan_text(text)
        result["file_path"] = str(path)
        result["file_size"] = size
        return result

    # ── Group E: Local Scanning ────────────────────────────────────

    def local_scan_run(
        self,
        scan_type: str = "credential",
        path: Optional[str] = None,
        max_files: int = 100,
    ) -> dict:
        """Run an on-demand local filesystem security scan."""
        scan_path = path or str(Path.home())

        try:
            from claw_vault.local_scan.models import ScanType
            from claw_vault.local_scan.scanner import LocalScanner

            try:
                st = ScanType(scan_type)
            except ValueError:
                return {
                    "success": False,
                    "error": f"Invalid scan type: {scan_type}",
                    "valid_types": ["credential", "vulnerability", "skill_audit"],
                }

            scanner = LocalScanner()
            result = scanner.run_scan(st, scan_path, max_files)

            findings = []
            for f in result.findings:
                findings.append({
                    "file_path": f.file_path,
                    "finding_type": f.finding_type,
                    "description": f.description,
                    "risk_score": f.risk_score,
                })

            return {
                "success": result.status.value != "failed",
                "scan_type": scan_type,
                "path": scan_path,
                "files_scanned": result.files_scanned,
                "findings_count": len(result.findings),
                "findings": findings,
                "max_risk_score": result.max_risk_score,
                "threat_level": result.threat_level,
                "duration_seconds": result.duration_seconds,
            }

        except ImportError:
            # Fallback: use CLI
            return self._local_scan_via_cli(scan_type, scan_path, max_files)

    def _local_scan_via_cli(self, scan_type: str, path: str, max_files: int) -> dict:
        """Fallback local scan using CLI."""
        try:
            result = subprocess.run(
                [
                    sys.executable, "-m", "claw_vault", "local-scan", "run",
                    "--type", scan_type,
                    "--path", path,
                    "--max-files", str(max_files),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout[:2000],
                "error": result.stderr[:500] if result.returncode != 0 else None,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def scan_schedule_add(
        self,
        cron: str,
        scan_type: str = "credential",
        path: Optional[str] = None,
        max_files: int = 100,
        config_path: Optional[str] = None,
    ) -> dict:
        """Add a cron-scheduled local scan."""
        # Validate cron expression
        try:
            from croniter import croniter

            if not croniter.is_valid(cron):
                return {"success": False, "error": f"Invalid cron expression: {cron}"}
        except ImportError:
            pass  # Skip validation if croniter not available

        valid_types = ["credential", "vulnerability", "skill_audit"]
        if scan_type not in valid_types:
            return {
                "success": False,
                "error": f"Invalid scan type: {scan_type}",
                "valid_types": valid_types,
            }

        config = self._load_config(config_path)

        if "local_scan" not in config:
            config["local_scan"] = {}
        if "schedules" not in config["local_scan"]:
            config["local_scan"]["schedules"] = []

        import uuid

        schedule_id = f"sched-{uuid.uuid4().hex[:8]}"
        schedule = {
            "id": schedule_id,
            "cron": cron,
            "scan_type": scan_type,
            "path": path or str(Path.home()),
            "max_files": max_files,
            "enabled": True,
        }
        config["local_scan"]["schedules"].append(schedule)

        saved_path = self._save_config(config, config_path)

        return {
            "success": True,
            "schedule_id": schedule_id,
            "schedule": schedule,
            "config_path": saved_path,
        }

    def scan_schedule_list(self, config_path: Optional[str] = None) -> dict:
        """List all configured scan schedules."""
        config = self._load_config(config_path)
        schedules = config.get("local_scan", {}).get("schedules", [])

        return {
            "success": True,
            "schedules": schedules,
            "count": len(schedules),
        }

    def scan_schedule_remove(self, schedule_id: str, config_path: Optional[str] = None) -> dict:
        """Remove a scheduled scan by ID."""
        config = self._load_config(config_path)

        local_scan = config.get("local_scan", {})
        schedules = local_scan.get("schedules", [])
        before = len(schedules)
        schedules = [s for s in schedules if s.get("id") != schedule_id]

        if len(schedules) == before:
            return {"success": False, "error": f"Schedule '{schedule_id}' not found"}

        local_scan["schedules"] = schedules
        config["local_scan"] = local_scan
        saved_path = self._save_config(config, config_path)

        return {
            "success": True,
            "removed": schedule_id,
            "config_path": saved_path,
        }

    def scan_history(self, limit: int = 20) -> dict:
        """Show recent local scan results."""
        history_file = self.config_dir / "data" / "local_scan_history.jsonl"

        if not history_file.exists():
            return {"success": True, "results": [], "count": 0}

        entries = []
        try:
            for line in history_file.read_text(encoding="utf-8").strip().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    entries.append({
                        "timestamp": entry.get("timestamp", ""),
                        "scan_type": entry.get("scan_type", ""),
                        "path": entry.get("path", ""),
                        "files_scanned": entry.get("files_scanned", 0),
                        "findings_count": len(entry.get("findings", [])),
                        "max_risk_score": entry.get("max_risk_score", 0),
                        "threat_level": entry.get("threat_level", ""),
                        "status": entry.get("status", ""),
                        "duration_seconds": entry.get("duration_seconds", 0),
                    })
                except (json.JSONDecodeError, KeyError):
                    continue
        except Exception as e:
            return {"success": False, "error": f"Failed to read history: {e}"}

        entries.reverse()
        entries = entries[:limit]

        return {"success": True, "results": entries, "count": len(entries)}

    # ── Group F: Agent Management ──────────────────────────────────

    def agent_list(self) -> dict:
        """List all registered agents and their configurations."""
        api_used, api_resp = self._api_request("GET", "/api/agents")
        if api_used and api_resp is not None:
            agents = api_resp if isinstance(api_resp, list) else api_resp.get("agents", [])
            return {"success": True, "agents": agents, "count": len(agents), "source": "api"}

        # File fallback
        config = self._load_config()
        entries = config.get("agents", {}).get("entries", {})
        agents = []
        for aid, agent in entries.items():
            agents.append({
                "id": aid,
                "name": agent.get("name", aid),
                "enabled": agent.get("enabled", True),
                "guard_mode": agent.get("guard_mode", "interactive"),
                "detection": agent.get("detection", {}),
            })
        return {"success": True, "agents": agents, "count": len(agents), "source": "file"}

    def agent_set(
        self,
        name: str,
        enabled: Optional[bool] = None,
        guard_mode: Optional[str] = None,
        detection_overrides: Optional[dict[str, bool]] = None,
        description: str = "",
    ) -> dict:
        """Create or update an agent configuration.

        Use detection_overrides to disable specific detection categories for
        this agent (e.g., {"prompt_injection": False, "dangerous_commands": False}
        to avoid self-triggering when managing vault configs).
        """
        # Build detection dict: start with all-True defaults, apply overrides
        detection = {
            "api_keys": True,
            "aws_credentials": True,
            "blockchain": True,
            "passwords": True,
            "private_ips": True,
            "pii": True,
            "jwt_tokens": True,
            "ssh_keys": True,
            "credit_cards": True,
            "emails": True,
            "generic_secrets": True,
            "dangerous_commands": True,
            "prompt_injection": True,
        }
        if detection_overrides:
            detection.update(detection_overrides)

        body: dict[str, Any] = {
            "name": name,
            "description": description,
            "detection": detection,
        }
        if enabled is not None:
            body["enabled"] = enabled
        else:
            body["enabled"] = True
        if guard_mode is not None:
            body["guard_mode"] = guard_mode
        else:
            body["guard_mode"] = "interactive"

        # Try API first
        api_used, api_resp = self._api_request("POST", "/api/agents", json_body=body)
        if api_used and api_resp:
            return {
                "success": True,
                "agent": api_resp,
                "source": "api",
            }

        # File fallback: write directly to config
        config = self._load_config()
        agents_section = config.setdefault("agents", {})
        entries = agents_section.setdefault("entries", {})

        # Find existing by name or create new
        import uuid

        agent_id = None
        for aid, agent in entries.items():
            if agent.get("name") == name:
                agent_id = aid
                break
        if not agent_id:
            agent_id = str(uuid.uuid4())[:8]

        entries[agent_id] = body
        self._save_config(config)

        return {
            "success": True,
            "agent": {"id": agent_id, **body},
            "source": "file",
            "warning": "Restart ClawVault for changes to take effect",
        }

    def agent_remove(self, agent_id: str) -> dict:
        """Remove an agent configuration."""
        # Try API first
        api_used, api_resp = self._api_request("DELETE", f"/api/agents/{agent_id}")
        if api_used and api_resp:
            if api_resp.get("deleted"):
                return {"success": True, "deleted": agent_id, "source": "api"}
            return {"success": False, "error": api_resp.get("error", "Agent not found")}

        # File fallback
        config = self._load_config()
        entries = config.get("agents", {}).get("entries", {})

        if agent_id not in entries:
            # Try match by name
            matched_id = None
            for aid, agent in entries.items():
                if agent.get("name") == agent_id:
                    matched_id = aid
                    break
            if matched_id:
                agent_id = matched_id
            else:
                return {
                    "success": False,
                    "error": f"Agent '{agent_id}' not found",
                    "available": list(entries.keys()),
                }

        del entries[agent_id]
        self._save_config(config)
        return {"success": True, "deleted": agent_id, "source": "file"}


def main():
    parser = argparse.ArgumentParser(
        description="ClawVault Operations - Manage services, config, vault, and scanning",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # start
    start_p = subparsers.add_parser("start", help="Start ClawVault services")
    start_p.add_argument("--port", type=int, default=8765, help="Proxy port")
    start_p.add_argument("--dashboard-port", type=int, default=8766, help="Dashboard port")
    start_p.add_argument("--dashboard-host", default="127.0.0.1", help="Dashboard host")
    start_p.add_argument("--mode", choices=["permissive", "interactive", "strict"], help="Guard mode")
    start_p.add_argument("--no-dashboard", action="store_true", help="Disable dashboard")
    start_p.add_argument("--json", action="store_true", help="Output JSON")

    # stop
    stop_p = subparsers.add_parser("stop", help="Stop ClawVault services")
    stop_p.add_argument("--force", action="store_true", help="Force kill")
    stop_p.add_argument("--json", action="store_true", help="Output JSON")

    # status
    status_p = subparsers.add_parser("status", help="Check service status")
    status_p.add_argument("--proxy-port", type=int, default=8765)
    status_p.add_argument("--dashboard-port", type=int, default=8766)
    status_p.add_argument("--dashboard-host", default="127.0.0.1")
    status_p.add_argument("--json", action="store_true", help="Output JSON")

    # scan
    scan_p = subparsers.add_parser("scan", help="Scan text for threats")
    scan_p.add_argument("text", help="Text to scan")
    scan_p.add_argument("--json", action="store_true", help="Output JSON")

    # scan-file
    scan_file_p = subparsers.add_parser("scan-file", help="Scan a file")
    scan_file_p.add_argument("file_path", help="File to scan")
    scan_file_p.add_argument("--json", action="store_true", help="Output JSON")

    # config-show
    cfg_show_p = subparsers.add_parser("config-show", help="Show configuration")
    cfg_show_p.add_argument("--config", help="Config file path")
    cfg_show_p.add_argument("--json", action="store_true", help="Output JSON")

    # config-get
    cfg_get_p = subparsers.add_parser("config-get", help="Get config value")
    cfg_get_p.add_argument("key", help="Dotted key (e.g. guard.mode)")
    cfg_get_p.add_argument("--config", help="Config file path")
    cfg_get_p.add_argument("--json", action="store_true", help="Output JSON")

    # config-set
    cfg_set_p = subparsers.add_parser("config-set", help="Set config value")
    cfg_set_p.add_argument("key", help="Dotted key (e.g. guard.mode)")
    cfg_set_p.add_argument("value", help="Value to set")
    cfg_set_p.add_argument("--config", help="Config file path")
    cfg_set_p.add_argument("--json", action="store_true", help="Output JSON")

    # config-append
    cfg_app_p = subparsers.add_parser("config-append", help="Append value to a list config field")
    cfg_app_p.add_argument("key", help="Dotted key (e.g. file_monitor.watch_paths)")
    cfg_app_p.add_argument("value", help="Value to append")
    cfg_app_p.add_argument("--config", help="Config file path")
    cfg_app_p.add_argument("--json", action="store_true", help="Output JSON")

    # config-remove
    cfg_rem_p = subparsers.add_parser("config-remove", help="Remove value from a list config field")
    cfg_rem_p.add_argument("key", help="Dotted key (e.g. file_monitor.watch_paths)")
    cfg_rem_p.add_argument("value", help="Value to remove")
    cfg_rem_p.add_argument("--config", help="Config file path")
    cfg_rem_p.add_argument("--json", action="store_true", help="Output JSON")

    # vault-list
    vl_p = subparsers.add_parser("vault-list", help="List vault presets")
    vl_p.add_argument("--config", help="Config file path")
    vl_p.add_argument("--json", action="store_true", help="Output JSON")

    # vault-show
    vs_p = subparsers.add_parser("vault-show", help="Show vault preset")
    vs_p.add_argument("preset_id", help="Preset ID")
    vs_p.add_argument("--config", help="Config file path")
    vs_p.add_argument("--json", action="store_true", help="Output JSON")

    # vault-apply
    va_p = subparsers.add_parser("vault-apply", help="Apply vault preset (hot-patches if dashboard running)")
    va_p.add_argument("preset_id", help="Preset ID to apply")
    va_p.add_argument("--config", help="Config file path")
    va_p.add_argument("--json", action="store_true", help="Output JSON")

    # vault-create
    vc_p = subparsers.add_parser("vault-create", help="Create custom vault preset from current config")
    vc_p.add_argument("name", help="Preset name")
    vc_p.add_argument("--id", dest="preset_id", help="Custom preset ID (auto-generated if omitted)")
    vc_p.add_argument("--description", default="", help="Preset description")
    vc_p.add_argument("--icon", default="\U0001f512", help="Preset icon emoji")
    vc_p.add_argument("--config", help="Config file path")
    vc_p.add_argument("--json", action="store_true", help="Output JSON")

    # vault-update
    vu_p = subparsers.add_parser("vault-update", help="Update custom vault preset")
    vu_p.add_argument("preset_id", help="Preset ID to update")
    vu_p.add_argument("--name", help="New name")
    vu_p.add_argument("--description", help="New description")
    vu_p.add_argument("--icon", help="New icon")
    vu_p.add_argument("--from-current", action="store_true", help="Re-snapshot current config into preset")
    vu_p.add_argument("--config", help="Config file path")
    vu_p.add_argument("--json", action="store_true", help="Output JSON")

    # vault-delete
    vd_p = subparsers.add_parser("vault-delete", help="Delete custom vault preset")
    vd_p.add_argument("preset_id", help="Preset ID to delete")
    vd_p.add_argument("--config", help="Config file path")
    vd_p.add_argument("--json", action="store_true", help="Output JSON")

    # vault-active
    vact_p = subparsers.add_parser("vault-active", help="Show active vault preset")
    vact_p.add_argument("--config", help="Config file path")
    vact_p.add_argument("--json", action="store_true", help="Output JSON")

    # local-scan
    ls_p = subparsers.add_parser("local-scan", help="Run local scan")
    ls_p.add_argument("--type", dest="scan_type", default="credential",
                       choices=["credential", "vulnerability", "skill_audit"])
    ls_p.add_argument("--path", help="Directory to scan")
    ls_p.add_argument("--max-files", type=int, default=100)
    ls_p.add_argument("--json", action="store_true", help="Output JSON")

    # scan-schedule-add
    ssa_p = subparsers.add_parser("scan-schedule-add", help="Add scheduled scan")
    ssa_p.add_argument("--cron", required=True, help="Cron expression")
    ssa_p.add_argument("--type", dest="scan_type", default="credential")
    ssa_p.add_argument("--path", help="Directory to scan")
    ssa_p.add_argument("--max-files", type=int, default=100)
    ssa_p.add_argument("--config", help="Config file path")
    ssa_p.add_argument("--json", action="store_true", help="Output JSON")

    # scan-schedule-list
    ssl_p = subparsers.add_parser("scan-schedule-list", help="List scheduled scans")
    ssl_p.add_argument("--config", help="Config file path")
    ssl_p.add_argument("--json", action="store_true", help="Output JSON")

    # scan-schedule-remove
    ssr_p = subparsers.add_parser("scan-schedule-remove", help="Remove scheduled scan")
    ssr_p.add_argument("schedule_id", help="Schedule ID to remove")
    ssr_p.add_argument("--config", help="Config file path")
    ssr_p.add_argument("--json", action="store_true", help="Output JSON")

    # scan-history
    sh_p = subparsers.add_parser("scan-history", help="Show scan history")
    sh_p.add_argument("--limit", type=int, default=20)
    sh_p.add_argument("--json", action="store_true", help="Output JSON")

    # agent-list
    al_p = subparsers.add_parser("agent-list", help="List registered agents")
    al_p.add_argument("--json", action="store_true", help="Output JSON")

    # agent-set
    as_p = subparsers.add_parser(
        "agent-set",
        help="Create/update agent config (use --no-* flags to disable detection categories)",
    )
    as_p.add_argument("name", help="Agent name")
    as_p.add_argument("--guard-mode", choices=["permissive", "interactive", "strict"], help="Guard mode")
    as_p.add_argument("--description", default="", help="Agent description")
    as_grp = as_p.add_mutually_exclusive_group()
    as_grp.add_argument("--enabled", action="store_true", default=None, help="Enable scanning")
    as_grp.add_argument("--disabled", action="store_true", default=None, help="Disable all scanning")
    # Detection category overrides (--no-* to disable)
    as_p.add_argument("--no-api-keys", action="store_true", help="Disable API key detection")
    as_p.add_argument("--no-aws-credentials", action="store_true", help="Disable AWS credential detection")
    as_p.add_argument("--no-passwords", action="store_true", help="Disable password detection")
    as_p.add_argument("--no-pii", action="store_true", help="Disable PII detection")
    as_p.add_argument("--no-jwt-tokens", action="store_true", help="Disable JWT detection")
    as_p.add_argument("--no-ssh-keys", action="store_true", help="Disable SSH key detection")
    as_p.add_argument("--no-credit-cards", action="store_true", help="Disable credit card detection")
    as_p.add_argument("--no-emails", action="store_true", help="Disable email detection")
    as_p.add_argument("--no-generic-secrets", action="store_true", help="Disable generic secret detection")
    as_p.add_argument("--no-dangerous-commands", action="store_true", help="Disable dangerous command detection")
    as_p.add_argument("--no-prompt-injection", action="store_true", help="Disable prompt injection detection")
    as_p.add_argument("--no-blockchain", action="store_true", help="Disable blockchain detection")
    as_p.add_argument("--no-private-ips", action="store_true", help="Disable private IP detection")
    as_p.add_argument("--json", action="store_true", help="Output JSON")

    # agent-remove
    ar_p = subparsers.add_parser("agent-remove", help="Remove agent config")
    ar_p.add_argument("agent_id", help="Agent ID or name to remove")
    ar_p.add_argument("--json", action="store_true", help="Output JSON")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Check that ClawVault is installed (venv exists)
    venv_python = Path.home() / ".clawvault-env" / "bin" / "python3"
    if not venv_python.exists():
        msg = (
            "ClawVault is not installed. Install it first:\n"
            "  openclaw skills install tophant-clawvault-installer\n"
            "  /tophant-clawvault-installer install --mode quick\n"
            "Or manually: pip install git+https://github.com/tophant-ai/ClawVault.git"
        )
        if getattr(args, "json", False):
            print(json.dumps({"success": False, "error": "not_installed", "message": msg}))
        else:
            print(f"ERROR: {msg}")
        sys.exit(1)

    ops = ClawVaultOps()
    result = {}

    if args.command == "start":
        result = ops.start(
            port=args.port,
            dashboard_port=args.dashboard_port,
            dashboard_host=args.dashboard_host,
            mode=args.mode,
            no_dashboard=args.no_dashboard,
        )
        if not args.json:
            if result.get("success"):
                print(f"ClawVault started (PID: {result.get('pid')})")
                print(f"  Proxy:     port {result['proxy']['port']} ({'running' if result['proxy']['running'] else 'starting'})")
                if result.get("dashboard", {}).get("running"):
                    print(f"  Dashboard: http://{result['dashboard'].get('host', '127.0.0.1')}:{result['dashboard']['port']}")
                if result.get("mode"):
                    print(f"  Mode:      {result['mode']}")
            else:
                print(f"Failed to start: {result.get('error', 'unknown')}")

    elif args.command == "stop":
        result = ops.stop(force=args.force)
        if not args.json:
            print(result.get("message", ""))
            if result.get("stopped_pids"):
                print(f"  Stopped PIDs: {result['stopped_pids']}")

    elif args.command == "status":
        result = ops.check_status(
            proxy_port=args.proxy_port,
            dashboard_port=args.dashboard_port,
            dashboard_host=args.dashboard_host,
        )
        if not args.json:
            proxy = result["proxy"]
            dash = result["dashboard"]
            p_status = "Running" if proxy["running"] else "Stopped"
            d_status = "Running" if dash["running"] else "Stopped"
            print(f"Proxy:     {p_status} (port {proxy['port']})")
            print(f"Dashboard: {d_status} (http://{dash['host']}:{dash['port']})")
            print(f"Active:    {result['active']}")

    elif args.command == "scan":
        result = ops.scan_text(args.text)
        if not args.json:
            if result.get("has_threats"):
                print(f"Threat Level: {result.get('threat_level', '?').upper()} (max score: {result.get('max_risk_score', 0):.1f})")
                for f in result.get("findings", []):
                    print(f"  [{f['type']}] {f.get('description', f.get('reason', '?'))} (risk: {f['risk_score']:.1f})")
            else:
                print("No threats detected.")

    elif args.command == "scan-file":
        result = ops.scan_file(args.file_path)
        if not args.json:
            if result.get("success"):
                print(f"File: {result.get('file_path')} ({result.get('file_size', 0)} bytes)")
                if result.get("has_threats"):
                    print(f"Threat Level: {result.get('threat_level', '?').upper()}")
                    for f in result.get("findings", []):
                        print(f"  [{f['type']}] {f.get('description', f.get('reason', '?'))} (risk: {f['risk_score']:.1f})")
                else:
                    print("No threats detected.")
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "config-show":
        result = ops.config_show(config_path=args.config)
        if not args.json:
            if result.get("success"):
                import yaml
                print(f"Config: {result['config_path']}\n")
                print(yaml.dump(result["config"], default_flow_style=False, allow_unicode=True, sort_keys=False))
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "config-get":
        result = ops.config_get(args.key, config_path=args.config)
        if not args.json:
            if result.get("success"):
                print(f"{result['key']} = {result['value']}")
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "config-set":
        result = ops.config_set(args.key, args.value, config_path=args.config)
        if not args.json:
            if result.get("success"):
                print(f"{result['key']}: {result['old_value']} -> {result['new_value']}")
                print(f"Saved to {result['config_path']}")
                if result.get("source") == "api":
                    print("  Hot-updated via dashboard API")
                if result.get("active_preset_cleared"):
                    print("  Active preset cleared (config drifted from preset)")
                if result.get("warning"):
                    print(result["warning"])
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "config-append":
        result = ops.config_append(args.key, args.value, config_path=args.config)
        if not args.json:
            if result.get("already_exists"):
                print(f"Value already in {result['key']}: {result['value']}")
                print(f"Current list: {result['current_list']}")
            elif result.get("success"):
                print(f"Added '{result['added']}' to {result['key']}")
                print(f"Current list: {result['current_list']}")
                if result.get("hot_updated"):
                    print("  Hot-updated via dashboard API")
                if result.get("active_preset_cleared"):
                    print("  Active preset cleared (config drifted from preset)")
                if result.get("warning"):
                    print(result["warning"])
            else:
                print(f"Error: {result.get('error')}")
                if result.get("hint"):
                    print(f"Hint: {result['hint']}")

    elif args.command == "config-remove":
        result = ops.config_remove(args.key, args.value, config_path=args.config)
        if not args.json:
            if result.get("success"):
                print(f"Removed '{result['removed']}' from {result['key']}")
                print(f"Current list: {result['current_list']}")
                if result.get("hot_updated"):
                    print("  Hot-updated via dashboard API")
                if result.get("active_preset_cleared"):
                    print("  Active preset cleared (config drifted from preset)")
                if result.get("warning"):
                    print(result["warning"])
            else:
                print(f"Error: {result.get('error')}")
                if result.get("current_list") is not None:
                    print(f"Current list: {result['current_list']}")

    elif args.command == "vault-list":
        result = ops.vault_list(config_path=args.config)
        if not args.json:
            if result["count"] == 0:
                print("No vault presets configured.")
            else:
                for p in result["presets"]:
                    builtin_tag = " [builtin]" if p["builtin"] else ""
                    print(f"  {p['icon']} {p['id']} - {p['name']} (mode: {p['guard_mode']}){builtin_tag}")
                print(f"\nTotal: {result['count']} presets")

    elif args.command == "vault-show":
        result = ops.vault_show(args.preset_id, config_path=args.config)
        if not args.json:
            if result.get("success"):
                import yaml
                p = result["preset"]
                print(f"{p.get('icon', '')} {p['name']} ({p['id']})")
                print(f"{p.get('description', '')}\n")
                print(yaml.dump({
                    "detection": p["detection"],
                    "guard": p["guard"],
                    "file_monitor": p["file_monitor"],
                    "rules": p["rules"],
                }, default_flow_style=False, allow_unicode=True, sort_keys=False))
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "vault-apply":
        result = ops.vault_apply(args.preset_id, config_path=args.config)
        if not args.json:
            if result.get("success"):
                print(f"Applied preset: {result.get('preset_name', result['preset_id'])}")
                print(f"  Guard mode: {result.get('guard_mode')}")
                source = result.get("source", "file")
                if source == "api":
                    print("  Hot-patched (no restart needed)")
                else:
                    print(f"  Saved to: {result.get('config_path')}")
                    print(result.get("warning", ""))
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "vault-create":
        result = ops.vault_create(
            name=args.name,
            description=args.description,
            icon=args.icon,
            preset_id=args.preset_id,
            config_path=args.config,
        )
        if not args.json:
            if result.get("success"):
                print(f"Created preset: {result.get('preset_name', '')} ({result.get('preset_id', '')})")
                print(f"  Source: {result.get('source', 'file')}")
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "vault-update":
        result = ops.vault_update(
            preset_id=args.preset_id,
            name=args.name,
            description=args.description,
            icon=args.icon,
            from_current=args.from_current,
            config_path=args.config,
        )
        if not args.json:
            if result.get("success"):
                print(f"Updated preset: {result.get('preset_id', '')}")
                print(f"  Updated fields: {', '.join(result.get('updated_fields', []))}")
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "vault-delete":
        result = ops.vault_delete(args.preset_id, config_path=args.config)
        if not args.json:
            if result.get("success"):
                print(f"Deleted preset: {result.get('deleted', '')}")
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "vault-active":
        result = ops.vault_active(config_path=args.config)
        if not args.json:
            active = result.get("active_preset_id")
            if active:
                print(f"Active preset: {active}")
            else:
                print("No active preset")

    elif args.command == "local-scan":
        result = ops.local_scan_run(
            scan_type=args.scan_type,
            path=args.path,
            max_files=args.max_files,
        )
        if not args.json:
            if result.get("success"):
                print(f"Scan: {result['scan_type']} on {result['path']}")
                print(f"  Files scanned: {result['files_scanned']}")
                print(f"  Findings: {result['findings_count']}")
                print(f"  Max risk: {result.get('max_risk_score', 0):.1f} ({result.get('threat_level', '?')})")
                print(f"  Duration: {result.get('duration_seconds', 0)}s")
                for f in result.get("findings", []):
                    print(f"  [{f['finding_type']}] {f['file_path']} - {f['description']} (risk: {f['risk_score']:.1f})")
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "scan-schedule-add":
        result = ops.scan_schedule_add(
            cron=args.cron,
            scan_type=args.scan_type,
            path=args.path,
            max_files=args.max_files,
            config_path=args.config,
        )
        if not args.json:
            if result.get("success"):
                s = result["schedule"]
                print(f"Added schedule: {s['id']}")
                print(f"  Cron: {s['cron']}")
                print(f"  Type: {s['scan_type']}")
                print(f"  Path: {s['path']}")
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "scan-schedule-list":
        result = ops.scan_schedule_list(config_path=args.config)
        if not args.json:
            if result["count"] == 0:
                print("No scheduled scans.")
            else:
                for s in result["schedules"]:
                    enabled = "enabled" if s.get("enabled", True) else "disabled"
                    print(f"  {s.get('id', '?')} | {s.get('cron', '?')} | {s.get('scan_type', '?')} | {s.get('path', '?')} [{enabled}]")

    elif args.command == "scan-schedule-remove":
        result = ops.scan_schedule_remove(args.schedule_id, config_path=args.config)
        if not args.json:
            if result.get("success"):
                print(f"Removed schedule: {result['removed']}")
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "scan-history":
        result = ops.scan_history(limit=args.limit)
        if not args.json:
            if result["count"] == 0:
                print("No scan history.")
            else:
                for e in result["results"]:
                    print(f"  {e['timestamp'][:19]} | {e['scan_type']} | {e['path'][:30]} | {e['files_scanned']} files | {e['findings_count']} findings | risk {e.get('max_risk_score', 0):.1f}")

    elif args.command == "agent-list":
        result = ops.agent_list()
        if not args.json:
            if result["count"] == 0:
                print("No agents registered.")
            else:
                for a in result["agents"]:
                    status = "enabled" if a.get("enabled", True) else "DISABLED"
                    mode = a.get("guard_mode", "?")
                    det = a.get("detection", {})
                    off = [k for k, v in det.items() if v is False]
                    off_str = f" (off: {', '.join(off)})" if off else ""
                    print(f"  {a.get('id', '?')} | {a.get('name', '?')} | {mode} | {status}{off_str}")
                print(f"\nTotal: {result['count']} agents")

    elif args.command == "agent-set":
        # Build detection overrides from --no-* flags
        detection_overrides = {}
        flag_map = {
            "no_api_keys": "api_keys",
            "no_aws_credentials": "aws_credentials",
            "no_passwords": "passwords",
            "no_pii": "pii",
            "no_jwt_tokens": "jwt_tokens",
            "no_ssh_keys": "ssh_keys",
            "no_credit_cards": "credit_cards",
            "no_emails": "emails",
            "no_generic_secrets": "generic_secrets",
            "no_dangerous_commands": "dangerous_commands",
            "no_prompt_injection": "prompt_injection",
            "no_blockchain": "blockchain",
            "no_private_ips": "private_ips",
        }
        for flag_name, category in flag_map.items():
            if getattr(args, flag_name, False):
                detection_overrides[category] = False

        enabled = None
        if args.enabled:
            enabled = True
        elif args.disabled:
            enabled = False

        result = ops.agent_set(
            name=args.name,
            enabled=enabled,
            guard_mode=args.guard_mode,
            detection_overrides=detection_overrides or None,
            description=args.description,
        )
        if not args.json:
            if result.get("success"):
                agent = result.get("agent", {})
                print(f"Agent configured: {agent.get('name', args.name)}")
                print(f"  ID: {agent.get('id', '?')}")
                print(f"  Mode: {agent.get('guard_mode', '?')}")
                print(f"  Enabled: {agent.get('enabled', True)}")
                det = agent.get("detection", {})
                off = [k for k, v in det.items() if v is False]
                if off:
                    print(f"  Disabled detections: {', '.join(off)}")
                if result.get("warning"):
                    print(result["warning"])
            else:
                print(f"Error: {result.get('error')}")

    elif args.command == "agent-remove":
        result = ops.agent_remove(args.agent_id)
        if not args.json:
            if result.get("success"):
                print(f"Removed agent: {result.get('deleted', '')}")
            else:
                print(f"Error: {result.get('error')}")

    # JSON output
    if args.json:
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))

    sys.exit(0 if result.get("success", True) else 1)


if __name__ == "__main__":
    main()
