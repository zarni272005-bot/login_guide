# Login and registration app

This project serves the login page and its Python account API from the same
origin. Accounts are stored in `instance/accounts.sqlite3`; passwords are
stored as Werkzeug password hashes, not plaintext. The app creates a local
session-signing key in `instance/flask_secret.key` on first run. Both runtime
files are excluded from Git.

## Run locally on Windows

From this folder, run:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Open `http://127.0.0.1:5000/` for login or
`http://127.0.0.1:5000/#register` to open registration directly.

Run the backend tests with:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The built-in Flask server is for local development. GitHub Pages serves static
files only and cannot run this backend; public account registration requires
deploying the Python app and its persistent database to a Python-capable host.
For HTTPS deployment, configure a strong `SECRET_KEY` environment variable and
set `COOKIE_SECURE=1`. Social sign-in buttons remain inactive until OAuth
providers are configured.
