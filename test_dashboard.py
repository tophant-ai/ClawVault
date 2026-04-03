#!/usr/bin/env python3
"""
Quick Dashboard Test Script
Starts the ClawVault dashboard for testing
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from claw_vault.config import load_settings
from claw_vault.dashboard.app import create_app
import uvicorn

def main():
    print("=" * 60)
    print("ClawVault Dashboard - Quick Test")
    print("=" * 60)

    # Load settings
    settings = load_settings()
    print(f"\nLoaded config with {len(settings.vaults.presets)} vault presets")

    # Create app
    app = create_app()

    port = settings.dashboard.port
    print(f"\nStarting dashboard server on port {port}...")
    print(f"Dashboard URL: http://localhost:{port}")
    print("\nPress Ctrl+C to stop\n")

    # Run server
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nStopping dashboard...")

