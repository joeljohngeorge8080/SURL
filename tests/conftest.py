"""
tests/conftest.py
Shared pytest configuration and fixtures.
"""
import sys
import os

# Ensure project root is on the path so all relative package imports work
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
