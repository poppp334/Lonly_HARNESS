import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
from core.embeddings import get_embedding_model, format_document_text, DEFAULT_EMBEDDING_MODEL

loader = DirectoryLoader("knowledge/", glob="**/*.md", loader_cls=TextLoader)
documents = loader.load()

if not documents:
    print("No documents found in knowledge/. Please add .md files.")
    exit(1)

# Utilize 8192 token context window with richer 1200-char chunks
splitter = RecursiveCharacterTextSplitter(chunk_size=1200, chunk_overlap=150)
chunks = splitter.split_documents(documents)

# Apply asymmetric document prefixing for nomic-embed-text
for chunk in chunks:
    chunk.page_content = format_document_text(chunk.page_content, DEFAULT_EMBEDDING_MODEL)

embeddings = get_embedding_model()

vectorstore = Chroma.from_documents(
    chunks, embeddings, persist_directory="chroma_db"
)

print(f"Successfully ingested {len(chunks)} chunks from {len(documents)} documents using {DEFAULT_EMBEDDING_MODEL}.")

