from flask import Flask, request    
from pypdf import PdfReader

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["files"]
    reader = PdfReader(file)
    text = ""
    for page in reader.pages:
        text += page.extract_text()
    return {"content": text}


if __name__ == "__main__":
    app.run(debug=True)
