from flask import Flask, render_template, request
from checker import analyze

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    error = None
    value = ""

    if request.method == "POST":
        value = request.form.get("ioc", "").strip()
        if not value:
            error = "Please enter a URL, IP address or file hash."
        elif len(value) > 500:
            error = "Input is too long (max 500 characters)."
        else:
            result = analyze(value)

    return render_template("index.html", result=result, error=error, value=value)


if __name__ == "__main__":
    app.run(debug=True)