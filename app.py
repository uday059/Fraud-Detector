import os
import hashlib
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"apk"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_sha256(filepath):
    sha256 = hashlib.sha256()

    with open(filepath, "rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def calculate_risk(filename, file_size):
    score = 10
    reasons = []

    lower_name = filename.lower()

    if file_size == 0:
        score += 50
        reasons.append("APK file is empty.")

    if file_size < 1000:
        score += 5
        reasons.append("APK file is unusually small.")

    suspicious_words = [
        "crack",
        "hack",
        "mod",
        "keygen",
        "cheat"
    ]

    found_words = []

    for word in suspicious_words:
        if word in lower_name:
            found_words.append(word)

    if found_words:
        score += 15
        reasons.append(
            "Suspicious keyword found in filename: "
            + ", ".join(found_words)
        )

    score = min(score, 100)

    if score <= 20:
        level = "VERY LOW RISK"
    elif score <= 40:
        level = "LOW RISK"
    elif score <= 60:
        level = "MEDIUM RISK"
    elif score <= 80:
        level = "HIGH RISK"
    else:
        level = "CRITICAL RISK"

    return score, level, reasons


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/scan")
def scan():
    return render_template("scan.html")


@app.route("/upload", methods=["POST"])
def upload():

    if "apk" not in request.files:
        return render_template(
            "scan.html",
            error="Please select an APK file."
        )

    file = request.files["apk"]

    if file.filename == "":
        return render_template(
            "scan.html",
            error="Please select an APK file."
        )

    if not allowed_file(file.filename):
        return render_template(
            "scan.html",
            error="Only .apk files are allowed."
        )

    filename = secure_filename(file.filename)

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(filepath)

    file_size = os.path.getsize(filepath)

    file_hash = get_sha256(filepath)

    risk_score, risk_level, risk_reasons = calculate_risk(
        filename,
        file_size
    )

    try:
        os.remove(filepath)
    except OSError:
        pass

    return render_template(
        "scan.html",
        filename=filename,
        file_size=file_size,
        file_hash=file_hash,
        risk_score=risk_score,
        risk_level=risk_level,
        risk_reasons=risk_reasons
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
    )