import hashlib
import os
from pathlib import Path
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from core.embeddings import get_embedding_model, format_document_text, DEFAULT_EMBEDDING_MODEL

ROOT_DIR = Path(__file__).resolve().parent
KNOWLEDGE_DIR = ROOT_DIR / "knowledge"
CHROMA_DIR = ROOT_DIR / "chroma_db"

loader = DirectoryLoader(str(KNOWLEDGE_DIR), glob="**/*.md", loader_cls=TextLoader)
documents = loader.load()

if not documents:
    print(f"No documents found in {KNOWLEDGE_DIR}. Please add .md files.")
    exit(1)

# Utilize 8192 token context window with richer 1200-char chunks
splitter = RecursiveCharacterTextSplitter(chunk_size=1200, chunk_overlap=150)
chunks = splitter.split_documents(documents)

# Apply asymmetric document prefixing for nomic-embed-text
for chunk in chunks:
    chunk.page_content = format_document_text(chunk.page_content, DEFAULT_EMBEDDING_MODEL)

embeddings = get_embedding_model()

# Deterministic IDs ensure idempotent ingestion across repeated runs (C9)
doc_ids = [
    hashlib.sha256(
        f"{chunk.metadata.get('source', '')}:{idx}:{chunk.page_content[:64]}".encode()
    ).hexdigest()
    for idx, chunk in enumerate(chunks)
]

vectorstore = Chroma(persist_directory=str(CHROMA_DIR), embedding_function=embeddings)
vectorstore.add_documents(chunks, ids=doc_ids)

print(f"Successfully ingested {len(chunks)} chunks from {len(documents)} documents into {CHROMA_DIR} using {DEFAULT_EMBEDDING_MODEL}.")

