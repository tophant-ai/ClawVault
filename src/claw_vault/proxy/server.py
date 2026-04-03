"""Proxy server management: start/stop mitmproxy with ClawVaultAddon."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Coroutine
from typing import TYPE_CHECKING, Any, cast

import structlog

from claw_vault.config import Settings
from claw_vault.detector.engine import DetectionEngine, ScanResult
from claw_vault.guard.rule_engine import RuleEngine
from claw_vault.monitor.token_counter import TokenCounter
from claw_vault.openclaw.service import OpenClawSessionRedactionService
from claw_vault.proxy.interceptor import ClawVaultAddon
from claw_vault.proxy.traffic_logger import ProxyTrafficLogger
from claw_vault.sanitizer.replacer import Sanitizer
from claw_vault.sanitizer.restorer import Restorer

logger = structlog.get_logger()

if TYPE_CHECKING:
    from mitmproxy.tools.dump import DumpMaster


class ProxyServer:
    """Manages the mitmproxy transparent proxy lifecycle."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._thread: threading.Thread | None = None
        self._master: DumpMaster | None = None

        # Initialize shared components
        self.token_counter = TokenCounter()
        self.sanitizer = Sanitizer()
        self.restorer = Restorer()
        self.detection_engine = DetectionEngine()
        self.rule_engine = RuleEngine(
            mode=settings.guard.mode,
            auto_sanitize=settings.guard.auto_sanitize,
        )
        self.openclaw_service = OpenClawSessionRedactionService(
            settings.openclaw.session_redaction,
            global_detection_config={
                "api_keys": settings.detection.api_keys,
                "aws_credentials": settings.detection.aws_credentials,
                "blockchain": settings.detection.blockchain,
                "passwords": settings.detection.passwords,
                "private_ips": settings.detection.private_ips,
                "pii": settings.detection.pii,
                "jwt_tokens": settings.detection.jwt_tokens,
                "ssh_keys": settings.detection.ssh_keys,
                "credit_cards": settings.detection.credit_cards,
                "emails": settings.detection.emails,
                "generic_secrets": settings.detection.generic_secrets,
                "dangerous_commands": settings.detection.dangerous_commands,
                "prompt_injection": settings.detection.prompt_injection,
            },
        )
        self.traffic_logger = ProxyTrafficLogger(
            path=settings.proxy.traffic_log_path,
            enabled=settings.proxy.traffic_log_enabled,
        )

        self.addon = ClawVaultAddon(
            detection_engine=self.detection_engine,
            rule_engine=self.rule_engine,
            sanitizer=self.sanitizer,
            restorer=self.restorer,
            token_counter=self.token_counter,
            intercept_hosts=settings.proxy.intercept_hosts,
            traffic_logger=self.traffic_logger,
        )

    def set_audit_callback(
        self,
        callback: Callable[[Any, Any | None], Coroutine[Any, Any, None]],
        main_loop: asyncio.AbstractEventLoop,
    ) -> None:
        """Wire an async audit callback from the main event loop.

        Since mitmproxy runs in a background thread (sync), we use
        ``asyncio.run_coroutine_threadsafe`` to bridge the gap.
        """

        def _threadsafe_callback(
            record: Any, scan: Any | None = None, request_body: Any | None = None,
        ) -> None:
            asyncio.run_coroutine_threadsafe(
                callback(record, scan, request_body=request_body), main_loop,
            )

        self.addon.audit_callback = _threadsafe_callback

    def start(self) -> None:
        """Start the proxy server in a background thread."""
        self.openclaw_service.start()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        logger.info(
            "proxy_started",
            host=self._settings.proxy.host,
            port=self._settings.proxy.port,
            traffic_log_path=str(self.traffic_logger.path),
            traffic_log_enabled=self._settings.proxy.traffic_log_enabled,
        )

    def _run(self) -> None:
        """Run mitmproxy in the background thread."""
        from mitmproxy.options import Options
        from mitmproxy.tools.dump import DumpMaster

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        opts = Options(
            listen_host=self._settings.proxy.host,
            listen_port=self._settings.proxy.port,
            ssl_insecure=not self._settings.proxy.ssl_verify,
        )

        async def run_master() -> None:
            master = DumpMaster(opts)
            self._master = master
            cast(Any, master).addons.add(self.addon)
            try:
                await cast(Any, master).run()
            except Exception as e:
                logger.error("proxy_error", error=str(e))

        loop.run_until_complete(run_master())

    def stop(self) -> None:
        """Stop the proxy server."""
        if self._master:
            cast(Any, self._master).shutdown()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)
        self.openclaw_service.stop()
        logger.info("proxy_stopped")

    # ── File Monitor Enforcement Pass-through ──

    def flag_file_content(self, file_path: str, scan: ScanResult) -> None:
        """Register sensitive values from a flagged file for proxy-level blocking."""
        self.addon.flag_file_content(file_path, scan)

    def unflag_file(self, file_path: str) -> None:
        """Remove a file from the flagged set."""
        self.addon.unflag_file(file_path)

    # ── Proxy Pause/Resume Pass-through ──

    def pause(self, reason: str, event_id: str | None = None) -> None:
        """Pause the proxy — all intercepted requests will be blocked."""
        self.addon.pause(reason, event_id)

    def resume(self) -> None:
        """Resume normal proxy operation."""
        self.addon.resume()

    @property
    def is_paused(self) -> bool:
        return self.addon.is_paused

    @property
    def pause_info(self) -> dict[str, Any] | None:
        return self.addon.pause_info
