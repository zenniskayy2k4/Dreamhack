from flask import Flask, render_template, request, jsonify, session
import os, secrets, random

app = Flask(__name__, static_folder="static", template_folder="templates")

app.secret_key = os.environ.get("???", "???")


def orig_is_green(coin_id: int) -> bool:
    return 0 <= coin_id < 10


@app.route("/")
def index():
    session.setdefault("streak", 0)
    session.pop("round", None)
    return render_template("index.html", streak=session["streak"])


@app.post("/start")
def start_round():
    token = secrets.token_urlsafe(16)
    rng = random.SystemRandom()
    left_ids = rng.sample(range(100), 10)
    session["round"] = {"token": token, "left": left_ids}
    return jsonify({"ok": True, "token": token, "left_ids": left_ids})


@app.post("/submit")
def submit():
    r = request.get_json(silent=True) or {}
    tok = r.get("round")
    toggled = r.get("toggled", [])

    round_state = session.get("round")
    if not round_state or round_state.get("token") != tok:
        return jsonify({"ok": False, "error": "round_mismatch"}), 400

    left_ids = set(int(x) for x in round_state["left"])
    toggled_set = {int(x) for x in toggled if x in left_ids and 0 <= int(x) < 100}

    left_green = sum((orig_is_green(cid) ^ (cid in toggled_set)) for cid in left_ids)
    right_green = sum(orig_is_green(cid) for cid in range(100) if cid not in left_ids)

    success = (left_green == right_green)

    if success:
        session["streak"] = session.get("streak", 0) + 1
    else:
        session["streak"] = 0

    session.pop("round", None)

    resp = {
        "ok": True,
        "success": success,
        "left_green": left_green,
        "right_green": right_green,
        "streak": session["streak"],
        "finished": False,
    }

    if success and session["streak"] >= 10:
        flag_path = os.path.join(os.path.dirname(__file__), "flag.txt")
        with open(flag_path, "r", encoding="utf-8") as f:
            resp["flag"] = f.read().strip()
        resp["finished"] = True

    return jsonify(resp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7000, debug=False)
