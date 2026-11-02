from flask import Flask, render_template, request
from parsers.ioc_parser import detect_ioc_type

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def home():

    # Store values for displaying on the page
    result = None
    ioc = None

    # Run analysis when form is submitted
    if request.method == "POST":

        ioc = request.form.get("ioc")

        # Determine IOC type
        result = detect_ioc_type(ioc)

    return render_template(
        "index.html",
        result=result,
        ioc=ioc
    )


if __name__ == "__main__":
    # Start Flask application
    app.run(debug=True)