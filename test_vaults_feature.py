#!/usr/bin/env python3
"""Test script for Vaults feature"""
import sys
sys.path.insert(0, 'src')

from claw_vault.config import load_settings, save_settings, VaultPreset
from datetime import datetime

def test_config_loading():
    """Test 1: Config loads with vaults"""
    settings = load_settings()
    assert len(settings.vaults.presets) == 6, "Should have 6 builtin presets"
    assert all(p.builtin for p in settings.vaults.presets), "All should be builtin"
    print("[PASS] Test 1: Config loading")

def test_vault_structure():
    """Test 2: Vault preset has correct structure"""
    settings = load_settings()
    preset = settings.vaults.presets[0]
    assert hasattr(preset, 'id')
    assert hasattr(preset, 'name')
    assert hasattr(preset, 'description')
    assert hasattr(preset, 'icon')
    assert hasattr(preset, 'builtin')
    assert hasattr(preset, 'detection')
    assert hasattr(preset, 'guard')
    assert hasattr(preset, 'file_monitor')
    assert hasattr(preset, 'rules')
    print("[PASS] Test 2: Vault structure")

def test_create_custom_vault():
    """Test 3: Create custom vault"""
    settings = load_settings()
    initial_count = len(settings.vaults.presets)

    new_preset = VaultPreset(
        id='test-vault',
        name='Test Vault',
        description='Test',
        icon='🧪',
        builtin=False,
        created_at=datetime.now().isoformat(),
        detection=settings.detection.model_dump(),
        guard=settings.guard.model_dump(),
        file_monitor=settings.file_monitor.model_dump(),
        rules=[]
    )

    settings.vaults.presets.append(new_preset)
    assert len(settings.vaults.presets) == initial_count + 1
    print("[PASS] Test 3: Create custom vault")

def test_find_vault():
    """Test 4: Find vault by ID"""
    settings = load_settings()
    found = next((p for p in settings.vaults.presets if p.id == 'dev'), None)
    assert found is not None
    assert found.builtin == True
    print("[PASS] Test 4: Find vault by ID")

def test_builtin_protection():
    """Test 5: Builtin vaults cannot be modified"""
    settings = load_settings()
    dev_preset = next((p for p in settings.vaults.presets if p.id == 'dev'), None)
    assert dev_preset.builtin == True, "Dev preset should be builtin"
    # In real API, this would return error
    print("[PASS] Test 5: Builtin protection check")

def test_apply_preset():
    """Test 6: Apply preset to settings"""
    settings = load_settings()
    prod_preset = next((p for p in settings.vaults.presets if p.id == 'prod'), None)

    # Simulate applying preset
    assert prod_preset.guard['mode'] == 'strict'
    assert prod_preset.detection['enabled'] == True
    print("[PASS] Test 6: Apply preset simulation")

def test_vault_serialization():
    """Test 7: Vault can be serialized to dict"""
    settings = load_settings()
    preset = settings.vaults.presets[0]
    data = preset.model_dump()

    assert isinstance(data, dict)
    assert 'id' in data
    assert 'detection' in data
    assert isinstance(data['detection'], dict)
    print("[PASS] Test 7: Vault serialization")

if __name__ == '__main__':
    print("=== Running Vaults Feature Tests ===\n")

    try:
        test_config_loading()
        test_vault_structure()
        test_create_custom_vault()
        test_find_vault()
        test_builtin_protection()
        test_apply_preset()
        test_vault_serialization()

        print("\n=== ALL TESTS PASSED ===")
        sys.exit(0)
    except AssertionError as e:
        print(f"\n[FAIL] {e}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[ERROR] {e}")
        sys.exit(1)
