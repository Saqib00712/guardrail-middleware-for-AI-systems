# Run it step by step (Windows cmd; Linux/macOS: use `export` instead of `set`)

One command per line. Run them in the same window.

## 1. Install (once)
```
cd guardrail-middleware
pip install -e ".[api]"
```

## 2. Check that everything passes
```
python -m pytest -q
python examples/quickstart.py
```

## 3. Make a key (once)
```
python -m guardrails.api.auth create --tenant acme --user alice --role user --scope inspect --keys-file keys.json
```
Copy the printed key (`gr_...`). It is shown only once.

## 4. Start the service in development mode
```
set GUARDRAILS_ENVIRONMENT=development
set GR_API_KEYS_FILE=keys.json
python -m guardrails.api
```
Leave this window open. The service is at `http://127.0.0.1:8000`.

## 5. Use the browser console
Open `http://127.0.0.1:8000/ui`. Paste the key, press **Check key**, pick a sample (email, fake key, injected document) and press **Run check**.
Green/amber/purple/red labels show allow, sanitize, require_review and block. The console exists only in development mode.
Interactive API docs are at `http://127.0.0.1:8000/docs` (also development only).

## 6. Or use the command line (second window)
```
curl -s -X POST http://127.0.0.1:8000/v1/inspect/input -H "Authorization: Bearer YOUR_KEY" -H "Content-Type: application/json" -d "{\"text\":\"my email is bob@example.com\"}"
```

## 7. Stop
Press Ctrl+C in the service window.

## Production
Not with the console. See `docs/operations.md`: an audit log and keys are required, and `/ui` and `/docs` are off.
