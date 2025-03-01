import os

from flask import Flask, jsonify, request
from flask_cors import CORS

from src.pyghira import decompile_and_objdump
from src.capa import capa_report

from src.virustotal import virustotal_report

app = Flask(__name__)
CORS(app)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.route("/decompile", methods=["POST"])
def decompile():
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


@app.route("/virustotal", methods=["POST"])
def virustotal():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    try:
        analysis_report = virustotal_report(filepath)
    except Exception as e:
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

    return jsonify({"analysis_report": analysis_report})


@app.route("/capa", methods=["POST"])
def capa():
    if "file" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)

    try:
        analysis_report = capa_report(filepath)
    except Exception as e:
        return jsonify({"error": f"Processing failed: {str(e)}"}), 500

    return jsonify({"capa_report": analysis_report})


if __name__ == "__main__":
    app.run(debug=True)
