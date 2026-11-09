"""Yabanin ML Classifier v1 — fast inference server for task complexity classification."""

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Optional

import numpy as np
import torch
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

logger = logging.getLogger("classifier")
logging.basicConfig(level=logging.INFO)

MODEL_PATH = os.environ.get("MODEL_PATH", "/app/model.pt")
# Device detection: prefer CUDA → MPS (Apple Silicon) → CPU
def _get_device():
    if torch.cuda.is_available():
        return "cuda"
    if hasattr(torch.backends, "mps") and torch.backends.mps.is_available():
        return "mps"
    return "cpu"

DEVICE = _get_device()


class ClassifyRequest(BaseModel):
    text: str
    org_id: Optional[str] = None


class ClassifyResponse(BaseModel):
    class_name: str  # easy, medium, hard
    confidence: float
    model_version: str = "v1.0"


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Loading classifier model...")
    tokenizer = AutoTokenizer.from_pretrained("BAAI/bge-small-en-v1.5")
    # Build a minimal 3-class head (we load the base encoder and add classification layers)
    model = _build_classifier(tokenizer)
    model.load_state_dict(torch.load(MODEL_PATH, map_location=DEVICE, weights_only=True))
    model.to(DEVICE)
    model.eval()
    app.state.tokenizer = tokenizer
    app.state.model = model
    logger.info(f"Model loaded on {DEVICE}")
    yield


def _build_classifier(tokenizer) -> AutoModelForSequenceClassification:
    """Build a 3-class classifier from bge-small base."""
    return AutoModelForSequenceClassification.from_pretrained(
        "BAAI/bge-small-en-v1.5",
        num_labels=3,
        ignore_mismatched_sizes=True,
    )


app = FastAPI(title="Yabanin ML Classifier v1", lifespan=lifespan)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/v1/classify", response_model=ClassifyResponse)
async def classify(req: ClassifyRequest):
    if not req.text or len(req.text.strip()) == 0:
        raise HTTPException(status_code=400, detail="text is required")

    start = time.time()
    tokenizer = app.state.tokenizer
    model = app.state.model

    inputs = tokenizer(
        req.text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
    ).to(DEVICE)

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.softmax(outputs.logits, dim=-1)
        confidence, class_idx = torch.max(probs, dim=-1)

    labels = ["easy", "medium", "hard"]
    class_name = labels[class_idx.item()]

    latency_ms = (time.time() - start) * 1000
    logger.info(f"classify: {class_name} conf={confidence.item():.3f} latency={latency_ms:.0f}ms")

    return ClassifyResponse(
        class_name=class_name,
        confidence=round(float(confidence.item()), 4),
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
