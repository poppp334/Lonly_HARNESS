#!/usr/bin/env python3
"""core/embeddings.py — Centralized Embedding Engine & Provider for LONLY v2.

Enforces:
- Single source of truth for RAG vector embeddings using native Ollama.
- High-performance, concurrent VRAM coexistence with generalist LLMs (phi4-mini).
- Asymmetric query/document prefixing (search_query: / search_document:) for nomic-embed-text.
- Dynamic environment variable configuration (LONLY_EMBEDDING_MODEL, LONLY_OLLAMA_URL).
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional

from langchain_ollama import OllamaEmbeddings

# Default model and service endpoint configuration
DEFAULT_EMBEDDING_MODEL = os.environ.get("LONLY_EMBEDDING_MODEL", "nomic-embed-text")
DEFAULT_OLLAMA_URL = os.environ.get(
    "LONLY_OLLAMA_URL",
    os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
)


def get_embedding_model(
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> OllamaEmbeddings:
    """Instantiate and return the centralized Ollama embedding model.

    Args:
        model: Model identifier (defaults to LONLY_EMBEDDING_MODEL or 'nomic-embed-text').
        base_url: Ollama API endpoint (defaults to LONLY_OLLAMA_URL or http://localhost:11434).

    Returns:
        Configured OllamaEmbeddings instance for ChromaDB or direct vector operations.
    """
    selected_model = model or DEFAULT_EMBEDDING_MODEL
    url = base_url or DEFAULT_OLLAMA_URL
    return OllamaEmbeddings(
        model=selected_model,
        base_url=url,
    )


def format_search_query(query: str, model_name: Optional[str] = None) -> str:
    """Prepend asymmetric search prefix for models like nomic-embed-text.

    nomic-embed-text is trained with task-specific prefixes:
    - Queries: 'search_query: <query>'
    - Documents: 'search_document: <chunk>'
    """
    m = (model_name or DEFAULT_EMBEDDING_MODEL).lower()
    q = query.strip()
    if "nomic" in m and not q.startswith("search_query:"):
        return f"search_query: {q}"
    return q


def format_document_text(text: str, model_name: Optional[str] = None) -> str:
    """Prepend document prefix for asymmetric models before indexing."""
    m = (model_name or DEFAULT_EMBEDDING_MODEL).lower()
    t = text.strip()
    if "nomic" in m and not t.startswith("search_document:"):
        return f"search_document: {t}"
    return t


def is_embedding_available(
    model: Optional[str] = None,
    base_url: Optional[str] = None,
) -> bool:
    """Check if the Ollama daemon is reachable and the embedding model is loaded."""
    selected_model = model or DEFAULT_EMBEDDING_MODEL
    url = (base_url or DEFAULT_OLLAMA_URL).rstrip("/")
    api_url = f"{url}/api/tags"

    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "LONLY-Embeddings-Check"})
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "").split(":")[0] for m in data.get("models", [])]
            return selected_model.split(":")[0] in models
    except Exception:
        return False
