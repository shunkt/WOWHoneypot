from flask import Flask, request

app = Flask(__name__)

print(__name__)


@app.route('/')
def index():
    return "ok"
