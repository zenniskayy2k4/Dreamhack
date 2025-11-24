import os
from flask import Flask, render_template, jsonify, request, session, send_file, abort
from flask import Flask, render_template, jsonify, request, session
import random

app = Flask(__name__)

FISHLIST_PATH = 'fishlist.txt'
FLAG_IMAGE_PATH = 'flag.jpg'


def load_fishes():
    fishes = []
    grade = None
    with open(FISHLIST_PATH, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("등급"):
                grade = line.split(":")[1].strip()
                continue
            if ' ' in line:
                name, prob = line.rsplit(' ', 1)
                prob = float(prob)
                fishes.append({
                    'name': name,
                    'img': f"{name}.jpg",
                    'prob': prob,
                    'grade': grade
                })
    return fishes


FISHES = load_fishes()
DEFAULT_PROBS = [fish['prob'] for fish in FISHES]


def pick_fish(fishes):
    r = random.random()
    total = 0
    for fish in fishes:
        total += fish['prob']
        if r < total:
            return fish
    return fishes[-1]


@app.route("/")
def index():
    caught = session.get("caught", [])
    return render_template("index.html", fishes=FISHES, caught=caught)


@app.route("/fish", methods=["POST"])
def fish():
    probs = request.form.getlist("probs", type=float)
    if len(probs) != len(FISHES):
        probs = DEFAULT_PROBS

    fishes = []
    for i, fish in enumerate(FISHES):
        fishes.append({
            "name": fish['name'],
            "img": fish['img'],
            "prob": probs[i],
            "grade": fish['grade']
        })

    fish = pick_fish(fishes)
    caught = session.get("caught", [])
    if fish['name'] not in caught:
        caught.append(fish['name'])
        session['caught'] = caught

    return jsonify({
        'name': fish['name'],
        'img': fish['img'],
        'grade': fish['grade']
    })


@app.route("/flag_image")
def flag_image():
    caught = session.get("caught", [])
    if "flag" in caught:
        if os.path.exists(FLAG_IMAGE_PATH):
            return send_file(FLAG_IMAGE_PATH, mimetype="image/jpeg")
        else:
            return abort(404)
    return abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
