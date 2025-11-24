from __future__ import annotations
import os
import time
import random
from dataclasses import dataclass, asdict, field
from typing import Dict, Any, List, Tuple
from datetime import timedelta
from flask import Flask, session, jsonify, render_template, request, Response

SECRET_KEY = "Fake_Key"

TICK_INTERVAL = float(os.environ.get("TICK_INTERVAL", "6.0"))
MIN_INTERVAL = float(os.environ.get("MIN_INTERVAL", "0.2"))  

SESSION_DAYS = int(os.environ.get("SESSION_DAYS", "3650"))     

BOOST_HEADER = os.environ.get("BOOST_HEADER", "X-Turbo")
BOOST_KEY = os.environ.get("BOOST_KEY", "banana")  

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
FLAG_PATH = os.path.join(APP_ROOT, "flag.txt")
FLAG_AGE = float(os.environ.get("FLAG_AGE", "10")) 

DECAY_PER_TICK = {
    "hunger": 3,      
    "happiness": -2,   
    "hygiene": -2,     
    "age": +0.01,      
}

POOP_SPAWN_PROB = float(os.environ.get("POOP_SPAWN_PROB", "0.12"))   
PET_REQ_PROB    = float(os.environ.get("PET_REQ_PROB", "0.10"))      
POOP_HYGIENE_PENALTY = float(os.environ.get("POOP_HYGIENE_PENALTY", "2"))  
PET_REQ_DURATION = float(os.environ.get("PET_REQ_DURATION", "18.0")) 
PET_REQ_OVERDUE_HAPPINESS_LOSS = float(os.environ.get("PET_REQ_OVERDUE_HAPPINESS_LOSS", "4"))  
POOP_MAX = int(os.environ.get("POOP_MAX", "5")) 

def clamp(x: float, lo: float = 0.0, hi: float = 100.0) -> float:
    return max(lo, min(hi, x))


@dataclass
class Pet:
    name: str = "Tama"
    hunger: float = 20.0
    happiness: float = 80.0
    hygiene: float = 80.0
    age: float = 0.0
    alive: bool = True
    last_tick: float = 0.0

    poops: List[Tuple[float, float]] = field(default_factory=list)
    pet_request_active: bool = False
    pet_request_until: float = 0.0  

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["age"] = round(self.age, 2)
        d["hunger"] = round(self.hunger, 1)
        d["happiness"] = round(self.happiness, 1)
        d["hygiene"] = round(self.hygiene, 1)
        return d

    def apply_tick(self, ticks: int, now: float, step: float) -> None:
        if not self.alive or ticks <= 0:
            return
        for _ in range(ticks):
            self.hunger = clamp(self.hunger + DECAY_PER_TICK["hunger"])
            self.happiness = clamp(self.happiness + DECAY_PER_TICK["happiness"])
            self.hygiene = clamp(self.hygiene + DECAY_PER_TICK["hygiene"])
            self.age += DECAY_PER_TICK["age"]

            if len(self.poops) > 0:
                self.hygiene = clamp(self.hygiene - POOP_HYGIENE_PENALTY)

            if self.pet_request_active and self.pet_request_until > 0 and now >= self.pet_request_until:
                self.happiness = clamp(self.happiness - PET_REQ_OVERDUE_HAPPINESS_LOSS)

            if self.hunger >= 100 or self.happiness <= 0 or self.hygiene <= 0:
                self.alive = False
                break

            if self.alive:
                if len(self.poops) < POOP_MAX and random.random() < POOP_SPAWN_PROB:
                    self.poops.append((random.random(), random.random()))
                if (not self.pet_request_active) and random.random() < PET_REQ_PROB:
                    self.pet_request_active = True
                    self.pet_request_until = now + PET_REQ_DURATION

            now += step  

    def act(self, action: str, data: Dict[str, Any] | None = None, now: float | None = None) -> None:
        if not self.alive:
            return
        data = data or {}
        now = now if now is not None else time.time()

        if action == "feed":
            before = self.hunger
            self.hunger = clamp(self.hunger - 25)
            if before - self.hunger < 10:
                self.happiness = clamp(self.happiness - 2)
            else:
                self.happiness = clamp(self.happiness + 1)

        elif action == "play":
            self.happiness = clamp(self.happiness + 12)
            self.hunger = clamp(self.hunger + 6)
            self.hygiene = clamp(self.hygiene - 4)

        elif action == "clean":
            self.hygiene = clamp(self.hygiene + 18)
            self.happiness = clamp(self.happiness + 2)

        elif action == "heal":
            self.happiness = clamp(self.happiness + 5)
            self.hygiene = clamp(self.hygiene + 5)

        elif action == "scoop": 
            if self.poops:
                self.poops.pop(0)
                self.hygiene = clamp(self.hygiene + 4)

        elif action == "pet":    
            if self.pet_request_active:
                self.pet_request_active = False
                self.pet_request_until = 0.0
                self.happiness = clamp(self.happiness + 6)

def create_app() -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.update(SECRET_KEY=SECRET_KEY)
    app.permanent_session_lifetime = timedelta(days=SESSION_DAYS)

    def get_tick_scale() -> float:
        try:
            s = float(session.get("tick_scale", 1.0))
        except Exception:
            s = 1.0
        return max(1.0, min(s, 50.0))

    def effective_interval() -> float:
        return max(MIN_INTERVAL, TICK_INTERVAL / get_tick_scale())

    def get_pet() -> Pet:
        session.permanent = True
        raw = session.get("pet")
        initialized = bool(session.get("name_set", False))

        if raw is None:
            pet = Pet(last_tick=time.time())
            session["pet"] = pet.to_dict()
            session["name_set"] = initialized
            session.modified = True
            return pet

        pet = Pet(**raw)

        now = time.time()
        last = pet.last_tick or now
        elapsed = max(0.0, now - last)

        step = effective_interval()
        ticks = int(elapsed // step)

        if ticks > 0:
            pet.apply_tick(ticks, now=last, step=step)
            pet.last_tick = now
            session["pet"] = pet.to_dict()
            session["name_set"] = initialized
            session.modified = True
        return pet

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.get("/state")
    def state():
        pet = get_pet()
        now = time.time()
        remaining = 0.0
        if pet.pet_request_active and pet.pet_request_until > 0:
            remaining = max(0.0, pet.pet_request_until - now)

        return jsonify({
            "ok": True,
            "pet": pet.to_dict(),
            "tick_interval": round(effective_interval(), 3),  
            "name_set": bool(session.get("name_set", False)),
            "poops": pet.poops,
            "poop_count": len(pet.poops),
            "poop_max": POOP_MAX,
            "pet_request_active": pet.pet_request_active,
            "pet_request_remaining": round(remaining, 1),
        })

    @app.post("/action")
    def do_action():
        pet = get_pet()
        try:
            payload = request.get_json(force=True, silent=True) or {}
        except Exception:
            payload = {}
        action = (payload.get("type") or "").strip().lower()
        if action not in {"feed", "play", "clean", "heal", "scoop", "pet"}:
            return jsonify({"ok": False, "error": "unknown action"}), 400
        pet.act(action, payload, now=time.time())
        pet.last_tick = time.time()
        session["pet"] = pet.to_dict()
        session.modified = True
        now = time.time()
        remaining = 0.0
        if pet.pet_request_active and pet.pet_request_until > 0:
            remaining = max(0.0, pet.pet_request_until - now)
        return jsonify({
            "ok": True,
            "pet": pet.to_dict(),
            "poops": pet.poops,
            "poop_count": len(pet.poops),
            "pet_request_active": pet.pet_request_active,
            "pet_request_remaining": round(remaining, 1),
        })

    @app.post("/reset")
    def reset():
        session.pop("pet", None)
        session.pop("name_set", None)
        session.pop("tick_scale", None)
        return jsonify({"ok": True})

    @app.post("/init_name")
    def init_name():
        try:
            payload = request.get_json(force=True, silent=True) or {}
        except Exception:
            payload = {}
        new_name = str(payload.get("name", "")).strip()
        if not new_name:
            return jsonify({"ok": False, "error": "name required"}), 400

        raw = session.get("pet")
        if raw is None:
            pet = Pet(last_tick=time.time())
        else:
            pet = Pet(**raw)

        pet.name = new_name[:16]
        pet.last_tick = time.time()

        session["pet"] = pet.to_dict()
        session["name_set"] = True
        session.permanent = True
        session.modified = True
        return jsonify({"ok": True, "pet": pet.to_dict()})

    @app.post("/dev/boost")
    def dev_boost():
        if request.headers.get(BOOST_HEADER) != BOOST_KEY:
            return jsonify({"ok": False, "error": "forbidden"}), 403
        data = request.get_json(silent=True) or {}
        try:
            x = float(data.get("x", 1.0))
        except Exception:
            x = 1.0
        x = max(1.0, min(x, 50.0)) 
        session["tick_scale"] = x
        session.modified = True
        return jsonify({"ok": True, "tick_scale": x, "effective_interval": max(MIN_INTERVAL, TICK_INTERVAL / x)})

    @app.post("/dev/boost/clear")
    def dev_boost_clear():
        if request.headers.get(BOOST_HEADER) != BOOST_KEY:
            return jsonify({"ok": False, "error": "forbidden"}), 403
        session["tick_scale"] = 1.0
        session.modified = True
        return jsonify({"ok": True, "tick_scale": 1.0, "effective_interval": TICK_INTERVAL})

    @app.get("/flag")
    def flag():
        pet = get_pet()
        if not bool(session.get("name_set", False)):
            return Response("forbidden", status=403, mimetype="text/plain")
        if pet.age < FLAG_AGE:
            return Response("forbidden", status=403, mimetype="text/plain")
        try:
            with open(FLAG_PATH, "r", encoding="utf-8") as f:
                txt = f.read().strip()
        except Exception:
            return Response("flag not found", status=500, mimetype="text/plain")
        resp = Response(txt, mimetype="text/plain; charset=utf-8")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.get("/healthz")
    def healthz():
        return "ok", 200

    return app

app = create_app()

if __name__ == "__main__":
    app.run(
        debug=False,
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )
