"""Ascend AI service entrypoint.

Assistant-only, per the AI philosophy in docs/CONSTITUTION.md: recommends,
organizes, summarizes, explains, automates — never silently takes control.
No assistant capability logic lives here yet; this is scaffolding.
"""

from fastapi import FastAPI

app = FastAPI(title="ascend-ai")


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}
