from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return "Flask Running on Vercel 🚀"

# IMPORTANT: expose WSGI app correctly
app = app