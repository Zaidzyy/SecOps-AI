"""Regression test for the .env load-order bug.

app_groq must call load_dotenv() BEFORE it imports config (and the other local
modules), because config.py reads SECOPS_SECRET_KEY via os.getenv at IMPORT
time. If .env is loaded after those imports, a key that lives ONLY in .env is
read as empty and the server refuses to start -- exactly what a user following
the README ("put SECOPS_SECRET_KEY in .env", then `python app_groq.py`) hits.

This runs in a fresh subprocess with NO SECOPS_SECRET_KEY in the environment, so
the ONLY place the key can come from is the .env file. `python -c` makes
python-dotenv's find_dotenv() search from the cwd (its __main__ has no __file__),
which lets us point it at an isolated temp .env instead of the repo's own.
"""
import os
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_secret_key_loads_from_dotenv_only(tmp_path):
    key = "only-in-dotenv-9f3c1a2b"
    (tmp_path / ".env").write_text(f"SECOPS_SECRET_KEY={key}\n", encoding="utf-8")

    # Strip any inherited SECOPS_SECRET_KEY: the whole point is that .env is the
    # sole source. Keep PYTHONPATH pointing at the repo (cwd is the temp dir) and
    # send the app's DB writes to a throwaway file so importing app_groq -- which
    # runs initialize_database() -- never touches the real system_metrics.db.
    env = dict(os.environ)
    env.pop("SECOPS_SECRET_KEY", None)
    env["PYTHONPATH"] = REPO_ROOT
    env["SECOPS_DB"] = str(tmp_path / "throwaway.db")

    # Import app_groq FIRST so its load_dotenv() runs before `import config`;
    # then confirm config picked the key up from the temp .env.
    code = (
        "import app_groq, config\n"
        f"assert config.SECRET_KEY == {key!r}, repr(config.SECRET_KEY)\n"
        "print('DOTENV_KEY_LOADED')\n"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(tmp_path), env=env,
        capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, f"stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert "DOTENV_KEY_LOADED" in proc.stdout, proc.stdout
