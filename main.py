import os

from flask import Flask, jsonify, request
from flask_cors import CORS

from tools.pyghira import decompile_and_objdump

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/decompile", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    try:
        decomplied_text, objdump_text = decompile_and_objdump(filepath)
    except Exception as e:
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

    return jsonify(
        {
            "decompiled_text": decomplied_text,
            "objdump_text": objdump_text,
        }
    )


if __name__ == "__main__":
    app.run(debug=True)
