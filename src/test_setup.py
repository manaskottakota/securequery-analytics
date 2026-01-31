import sys
print(f"Python version: {sys.version}")

try:
    import psycopg2
    import pandas as pd
    import cryptography
    import click
    print("✓ All dependencies installed successfully!")
except ImportError as e:
    print(f"✗ Missing dependency: {e}")
