from __future__ import annotations
from flask import Flask, render_template, request, jsonify
from pathlib import Path
import json
import re

app = Flask(__name__)

HEIGHT = 30   
WIDTH  = 200  
ANSWER_FILE = Path("answer.txt")


def parse_answer_file(path: Path, height: int, width: int) -> set[tuple[int, int]]:
    filled: set[tuple[int, int]] = set()
    if not path.exists():
        print(f"[!] {path} not found. Provide your answer file.")
        return filled

    rx = re.compile(r"^\s*(\d+)\s*[, ]\s*(\d+)\s*$")
    with path.open("r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = rx.match(line)
            if not m:
                print(f"skip line {ln}: {line!r}")
                continue
            r, c = int(m.group(1)), int(m.group(2))
            if 0 <= r < height and 0 <= c < width:
                filled.add((r, c))
            else:
                print(f"out-of-bounds ({r},{c}) at line {ln}; ignored")
    return filled


def runs_from_line(bits: list[int]) -> list[int]:
    runs = []
    cur = 0
    for b in bits:
        if b:
            cur += 1
        else:
            if cur:
                runs.append(cur)
                cur = 0
    if cur:
        runs.append(cur)
    return runs


def compute_clues(height: int, width: int, filled: set[tuple[int, int]]):
    row_clues: list[list[int]] = []
    for r in range(height):
        line = [1 if (r, c) in filled else 0 for c in range(width)]
        row_clues.append(runs_from_line(line))

    col_clues: list[list[int]] = []
    for c in range(width):
        line = [1 if (r, c) in filled else 0 for r in range(height)]
        col_clues.append(runs_from_line(line))
    return row_clues, col_clues


def load_puzzle():
    filled = parse_answer_file(ANSWER_FILE, HEIGHT, WIDTH)
    row_clues, col_clues = compute_clues(HEIGHT, WIDTH, filled)
    solution_count = len(filled)
    return {
        "height": HEIGHT,
        "width": WIDTH,
        "row_clues": row_clues,
        "col_clues": col_clues,
        "solution_count": solution_count,
        "solution": sorted(list(filled)),
    }


@app.route("/")
def index():
    data = load_puzzle()
    safe_data = dict(data)
    safe_data.pop("solution", None)
    return render_template("index.html", data_json=json.dumps(safe_data, ensure_ascii=False))


@app.route("/check", methods=["POST"])
def check():
    client = request.get_json(force=True, silent=True) or {}
    filled_client = client.get("filled") or []
    filled_client = {(int(r), int(c)) for r, c in filled_client}

    puzzle = load_puzzle()
    filled_true = set(map(tuple, puzzle["solution"]))

    extra = sorted(list(filled_client - filled_true))
    missing = sorted(list(filled_true - filled_client))
    ok = (len(extra) == 0 and len(missing) == 0)

    return jsonify({
        "ok": ok,
        "total": puzzle["solution_count"],
        "correct": puzzle["solution_count"] - len(missing),
        "extra": len(extra),
        "missing": len(missing),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
