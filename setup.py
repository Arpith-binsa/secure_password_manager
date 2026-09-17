import os
import subprocess
import sys
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parent
VENV = ROOT / ".venv"

def venv_python():
    if os.name == "nt":
        return VENV / "Scripts" / "python.exe"
    return VENV / "bin" / "python"

if not VENV.exists():
    print("Creating virtual environment...")
    venv.EnvBuilder(with_pip=True).create(VENV)

python = venv_python()

print("Installing required libraries...")
subprocess.check_call([str(python), "-m", "pip", "install", "--upgrade", "pip"])
subprocess.check_call([str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements.txt")])

print("Initialising SQLite database...")
env = os.environ.copy()
env["PYTHONPATH"] = str(ROOT)
subprocess.check_call([str(python), "-c", "from app import app, db; app.app_context().push(); db.create_all(); print('Database ready.')"], env=env)

print("\nSetup complete.")
print("Start the application with:")
if os.name == "nt":
    print("  .venv\\Scripts\\python.exe app.py")
else:
    print("  .venv/bin/python app.py")
print("\nThen open: http://127.0.0.1:5000")
