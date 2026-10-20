"""python -m guardrails.api  -> run the service (reads GR_* / GUARDRAILS_* environment variables)."""
import os

import uvicorn

from guardrails.api.config import build_app

if __name__ == "__main__":
    uvicorn.run(build_app(), host=os.environ.get("GR_HOST", "127.0.0.1"), port=int(os.environ.get("GR_PORT", "8000")),
                server_header=False)
