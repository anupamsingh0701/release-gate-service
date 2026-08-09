import logging
from typing import Any, Dict
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from policy import evaluate_release_gate

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("release-gate")

app = FastAPI(title="TDS GA7 Release Gate Policy Service")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def health_check():
    return {"status": "ok", "service": "TDS GA7 Release Gate Policy Service"}

@app.get("/release-gate")
def release_gate_get():
    return {"status": "ok", "message": "Send POST request to evaluate release gate policy."}

@app.post("/release-gate")
async def evaluate_endpoint(request: Request):
    try:
        body = await request.json()
    except Exception as e:
        logger.error(f"Invalid JSON payload: {e}")
        return JSONResponse(
            status_code=400,
            content={"decision": "block", "violations": ["INVALID_PAYLOAD"]}
        )
    
    decision, violations = evaluate_release_gate(body)
    logger.info(f"Evaluated request: decision={decision}, violations={violations}")
    return {"decision": decision, "violations": violations}

@app.post("/")
async def root_post_endpoint(request: Request):
    return await evaluate_endpoint(request)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True)
