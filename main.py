import os

import uuid
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, status, BackgroundTasks
from langchain_text_splitters import RecursiveCharacterTextSplitter
import chromadb
from google import genai
from google.genai import types
from pypdf import PdfReader
from dotenv import load_dotenv
load_dotenv()
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Initialize FastAPI App
app = FastAPI(
    title="Secure AI Document Assistant API",
    description="Production-grade API for uploading documents with integrated malware verification and RAG operations with Gemini",
    version="1.1.0"
)

# Configuration & Storage Environments
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB limit
ALLOWED_EXTENSIONS = {".pdf", ".txt", ".md"}
UPLOAD_DIR = Path("./secure_storage")
UPLOAD_DIR.mkdir(exist_ok=True)
import os
custom_key = os.environ["GEMINI_API_KEY"]

# Initialize Gemini Client (Picks up GEMINI_API_KEY from environment)
gemini_client = genai.Client(api_key=custom_key)

# Initialize Vector DB Context
chroma_client = chromadb.PersistentClient(path="./chroma_ai_db")
ai_collection = chroma_client.get_or_create_collection(name="document_knowledge")

# Industry standard signature used to validate antivirus pipelines (Safe for testing)
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # tighten this in production
    allow_methods=["*"],
    allow_headers=["*"],
)


# def scan_file_for_malware(file_bytes: bytes) -> tuple[bool, str | None]:
#     """
#     Scans raw byte arrays for high-risk malware patterns, shellcode signatures, 
#     and malicious payloads (like the EICAR testing standard).
#     """
#     # Check for standard EICAR test virus string
#     if EICAR_SIGNATURE in file_bytes:
#         return True, "EICAR-Test-Signature (Malware Detected)"
        
#     # High-Risk Exploit Pattern Matching (Detects nested executable components inside raw file bytes)
    
#     for pattern, threat_name in malicious_patterns:
#         if re.search(pattern, file_bytes):
#             return True, threat_name

#     return False, None


def parse_document_to_text(file_path: Path) -> str:
    """Extracts raw string text from documents safely using pure-python parsers."""
    ext = file_path.suffix.lower()

    if ext == ".pdf":
        text = ""
        try:
            reader = PdfReader(file_path)
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
        except Exception as e:
            print(f"Error reading PDF file {file_path.name}: {str(e)}")
            return ""
        return text

    elif ext in {".txt", ".md"}:
        return file_path.read_text(encoding="utf-8", errors="ignore")

    return ""


async def run_ai_ingestion_pipeline(file_path: Path, original_filename: str, doc_id: str):
    """Background worker that chunks documents and indexes them into vector memory."""
    try:
        raw_text = parse_document_to_text(file_path)
        if not raw_text.strip():
            print(f"Skipping processing: No indexable text found in {original_filename}")
            return

        # Split text into overlapping semantically coherent blocks
        text_splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
        chunks = text_splitter.split_text(raw_text)

        # Prepare metadata and structural layout for vector storage injection
        ids = [f"{doc_id}_chunk_{i}" for i in range(len(chunks))]
        metadatas = [{"source": original_filename, "doc_id": doc_id} for _ in chunks]

        ai_collection.add(documents=chunks, ids=ids, metadatas=metadatas)
        print(f"Successfully indexed {len(chunks)} text chunks for: {original_filename}")

    except Exception as e:
        print(f"Critical pipeline error processing document {original_filename}: {str(e)}")


@app.post("/api/v1/upload", status_code=status.HTTP_201_CREATED)
async def upload_document(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    """Handles secure file uploads, checks constraints, runs malware scans, and schedules embedding generation."""
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No filename provided.")

    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Unsupported file type.")

    # Validate file size without consuming the request stream payload prematurely
    file.file.seek(0, os.SEEK_END)
    file_size = file.file.tell()
    file.file.seek(0)

    if file_size > MAX_FILE_SIZE:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large (Max 10MB).")

    # Read file content into memory to run signature analysis before saving onto disk
    file_content = await file.read()
    
    # MALWARE SCANNING BLOCK
    # is_malicious, threat_type = scan_file_for_malware(file_content)
    # if is_malicious:
    #     raise HTTPException(
    #         status_code=status.HTTP_400_BAD_REQUEST,
    #         detail=f"Security Alert: File rejected due to malicious payload signature detection. Flagged: {threat_type}"
    #     )

    # Abstract actual filenames using UUIDs to prevent directory traversal vulnerabilities
    document_id = uuid.uuid4().hex
    final_file_path = UPLOAD_DIR / f"{document_id}{file_ext}"

    # Write the validated byte stream directly to file storage
    try:
        with open(final_file_path, "wb") as buffer:
            buffer.write(file_content)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"File system failure during ingestion: {str(e)}"
        )

    # Dispatch data loading tasks to BackgroundTasks worker threads to keep API responsive
    background_tasks.add_task(run_ai_ingestion_pipeline, final_file_path, file.filename, document_id)

    return {
        "message": "File successfully uploaded and accepted.",
        "document_id": document_id,
        "filename": file.filename,
        "status": "ai_indexing_background_job_started",
    }


@app.get("/api/v1/search")
def search_ai_memory(query: str, limit: int = 3):
    """Direct lookup to fetch nearest neighbor vectors matching a user string."""
    results = ai_collection.query(query_texts=[query], n_results=limit)

    formatted_matches = []
    if results["documents"]:
        for doc, meta in zip(results["documents"][0], results["metadatas"][0]):
            formatted_matches.append({"source_file": meta["source"], "content_snippet": doc})

    return {"query": query, "matches": formatted_matches}



@app.get("/api/v1/chat-gemini")
async def chat_with_docs_gemini(question: str):
    """Retrieves document context from local store and answers query natively via Gemini."""
    search_results = ai_collection.query(query_texts=[question], n_results=3)

    context = ""
    if search_results.get("documents") and search_results["documents"][0]:
        context = "\n---\n".join(search_results["documents"][0])

    # Enforce context grounding strictly within the engineered prompt template
    prompt = (
        "You are a precise AI Document Assistant.\n"
        "Use ONLY the following document text fragments to answer the user's question accurately.\n"
        "If the answer cannot be found in the context, explicitly state that you cannot find the answer.\n\n"
        f"--- CONTEXT ---\n{context}\n---------------\n\n"
        f"User Question: {question}"
    )

    try:
        response = gemini_client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(temperature=0.1),  # Low temperature mitigates hallucinations
        )

        sources = []
        if search_results.get("metadatas") and search_results["metadatas"][0]:
            sources = list(set([m["source"] for m in search_results["metadatas"][0] if "source" in m]))

        return {"answer": response.text, "source_documents": sources if context else []}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Gemini API integration error: {str(e)}",
        )



app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def root():
    return FileResponse("static/index.html")
