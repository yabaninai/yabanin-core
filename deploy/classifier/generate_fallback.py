#!/usr/bin/env python3
"""Generate a random classification head as fallback when no trained checkpoint exists."""
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

model = AutoModelForSequenceClassification.from_pretrained(
    'BAAI/bge-small-en-v1.5', num_labels=3, ignore_mismatched_sizes=True
)
torch.save(model.state_dict(), '/app/model.pt')
print('Fallback random head saved')
