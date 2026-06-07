import os
from langchain_community.document_loaders import DirectoryLoader, TextLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings   # <-- changed
from langchain_community.vectorstores import Chroma

loader = DirectoryLoader("knowledge/", glob="**/*.md", loader_cls=TextLoader)
documents = loader.load()

if not documents:
    print("No documents found in knowledge/. Please add .md files.")
    exit(1)

splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
chunks = splitter.split_documents(documents)

embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")   # <-- changed

vectorstore = Chroma.from_documents(
    chunks, embeddings, persist_directory="chroma_db"
)

print(f"Successfully ingested {len(chunks)} chunks from {len(documents)} documents.")
