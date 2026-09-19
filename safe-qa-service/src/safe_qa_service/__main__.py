"""Run the API with `python -m safe_qa_service`."""

import uvicorn

if __name__ == "__main__":
    uvicorn.run("safe_qa_service.app:app", host="0.0.0.0", port=8080)
