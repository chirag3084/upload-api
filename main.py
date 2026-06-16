import os
from typing import List, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(title="DocMind API", version="1.0.0")

# --- 1. PRODUCTION CORS SETUP ---
# Replace these with your actual production frontend URLs.
# The UI code allows you to change the API Base URL at the top right.
ALLOWED_ORIGINS = [
    "http://localhost:3000",      # Local frontend dev port
    "http://127.0.0.1:3000",
    "https://yourfrontend.com",    # Your production UI domain
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


# --- 2. DATA MODELS (Pydantic) ---
class SearchMatch(BaseModel):
    source_file: str
    content_snippet: str

class SearchResponse(BaseModel):
    matches: List[SearchMatch]

class ChatResponse(BaseModel):
    answer: str
    source_documents: List[str]


# --- 3. ENDPOINTS ---

@app.post("/api/v1/upload", status_code=200)
async def upload_document(file: UploadFile = File(...)):
    """
    Handles file upload & indexing (.pdf, .txt, .md).
    Matches UI call: POST /api/v1/upload
    """
    # Validate file extension
    extension = os.path.splitext(file.filename)[1].lower()
    if extension not in [".pdf", ".txt", ".md"]:
        raise HTTPException(
            status_code=400, 
            detail="Unsupported file type. Please upload a .pdf, .txt, or .md file."
        )
    
    try:
        # Read file contents
        contents = await file.read()
        file_size_kb = len(contents) / 1024
        
        # --- PLACEHOLDER FOR YOUR EMBEDDING/INDEXING LOGIC ---
        # e.g., text = extract_text(contents), vector_store.add(text)
        # -----------------------------------------------------

        return {
            "status": "success",
            "filename": file.filename,
            "size_kb": round(file_size_kb, 1),
            "message": "Document successfully uploaded and indexed into the vector database."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process document: {str(e)}")


@app.get("/api/v1/search", response_model=SearchResponse)
async def semantic_search(
    query: str = Query(..., description="The search string"), 
    limit: int = Query(3, ge=1, le=10)
):
    """
    Performs semantic vector search across documents.
    Matches UI call: GET /api/v1/search?query=...&limit=...
    """
    if not query.strip():
        raise HTTPException(status_code=400, detail="Search query cannot be empty.")

    # --- PLACEHOLDER FOR YOUR VECTOR DB QUERY LOGIC ---
    # mock data matching what the frontend expects:
    mock_matches = [
        SearchMatch(source_file="contract_draft.md", content_snippet=f"Found match containing details relevant to: '{query}'..."),
        SearchMatch(source_file="financial_report.pdf", content_snippet="The payment terms stipulate net-30 days processing from invoice generation."),
    ]
    # Filter down to the limit passed by the UI slider
    results = mock_matches[:limit]
    # --------------------------------------------------

    return SearchResponse(matches=results)


@app.get("/api/v1/chat-gemini", response_model=ChatResponse)
async def chat_with_gemini(
    question: str = Query(..., description="The user question for Gemini")
):
    """
    Context-aware Document Chat using Gemini.
    Matches UI call: GET /api/v1/chat-gemini?question=...
    """
    if not question.strip():
        raise HTTPException(status_code=400, detail="Question cannot be empty.")

    try:
        # --- PLACEHOLDER FOR YOUR RAG + GEMINI API CALL ---
        # 1. Search vector DB for context chunks
        # 2. Format context + question into a prompt
        # 3. Call google-genai SDK
        mock_answer = f"Based on your documents, here is the response to your question: '{question}'. All operations are running within the standard framework bounds."
        mock_sources = ["contract_draft.md", "financial_report.pdf"]
        # --------------------------------------------------

        return ChatResponse(
            answer=mock_answer,
            source_documents=mock_sources
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Gemini generation failed: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)