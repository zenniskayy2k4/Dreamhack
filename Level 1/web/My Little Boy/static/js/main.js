async function getState() {
  const res = await fetch("/state", { cache: "no-store" });
  if (!res.ok) throw new Error("state fetch failed");
  return await res.json();
}

async function doAction(type, extra = {}) {
  const res = await fetch("/action", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type, ...extra }),
  });
  if (!res.ok) throw new Error("action failed");
  return await res.json();
}

async function resetGame() {
  const res = await fetch("/reset", { method: "POST" });
  if (!res.ok) throw new Error("reset failed");
}

async function initName(name) {
  const res = await fetch("/init_name", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name }),
  });
  if (!res.ok) throw new Error("init_name failed");
  return await res.json();
}

function setBar(el, value, goodIsHigh = true) {
  const v = Math.max(0, Math.min(100, value));
  el.style.width = v + "%";
  let cls = "ok";
  if ((goodIsHigh && v < 30) || (!goodIsHigh && v > 70)) cls = "bad";
  else if ((goodIsHigh && v < 60) || (!goodIsHigh && v > 40)) cls = "warn";
  el.style.background =
    cls === "ok" ? "var(--ok)" : cls === "warn" ? "var(--warn)" : "var(--bad)";
}

function computeStatus(pet, extras) {
  const { poop_count, pet_request_active, pet_request_remaining } = extras;
  if (!pet.alive) return "…사망했습니다. 리셋하여 다시 시작하세요";

  const msgs = [];

  if (pet_request_active) {
    const sec = Math.ceil(pet_request_remaining || 0);
    const txt = sec > 0 ? `쓰다듬어 달라고 해요 (남은 시간 ${sec}s)` : "쓰다듬어 달라고 해요 (늦었어요!)";
    msgs.push(txt);
  }
  if (poop_count > 0) {
    msgs.push(`바닥이 지저분해요 ×${poop_count}`);
  }

  if (pet.hunger >= 85) msgs.push("몹시 배고파해요");
  else if (pet.hunger >= 70) msgs.push("배가 많이 고파요");
  else if (pet.hunger >= 45) msgs.push("슬슬 배가 고파요");

  if (pet.happiness <= 15) msgs.push("매우 우울해요");
  else if (pet.happiness <= 35) msgs.push("심심해해요");
  else if (pet.happiness >= 85) msgs.push("기분 최고!");

  if (pet.hygiene <= 15) msgs.push("아주 더러워서 찝찝해요");
  else if (pet.hygiene <= 35) msgs.push("씻고 싶어해요");

  if (msgs.length === 0) return "평온하게 돌아다니는 중입니다";
  return msgs.slice(0, 3).join(" · ");
}

function disableAllInteractions(disabled) {
  const controlButtons = document.querySelectorAll(".controls button");
  controlButtons.forEach((btn) => {
    if (btn.id === "reset") return;
    btn.disabled = disabled;
  });
  const inputs = document.querySelectorAll("input");
  inputs.forEach((inp) => (inp.disabled = disabled));
}

function renderPoops(poops) {
  const layer = document.getElementById("poop-layer");
  const room = document.getElementById("room");
  if (!layer || !room) return;

  layer.innerHTML = ""; 

  const w = room.clientWidth;
  const h = room.clientHeight;

  for (const [nx, ny] of poops) {
    const x = nx * w;
    const y = ny * h;
    const el = document.createElement("div");
    el.className = "poop";
    el.textContent = "💩";
    el.style.left = `${x}px`;
    el.style.top  = `${y}px`;
    layer.appendChild(el);
  }
}

let _flagLoaded = false;
let _flagCache = "";

async function toggleFlag(show) {
  const box = document.getElementById("flag-box");
  if (!box) return;

  if (show) {
    if (!_flagLoaded) {
      try {
        const res = await fetch("/flag", { cache: "no-store" });
        if (!res.ok) throw new Error("flag forbidden");
        _flagCache = await res.text();
        _flagLoaded = true;
      } catch (e) {
        _flagCache = "(flag fetch failed)";
      }
    }
    box.textContent = (_flagCache || "").trim();
    box.classList.remove("hidden");
  } else {
    box.classList.add("hidden");
  }
}

function updateUI(pet, tick, extras) {
  document.getElementById("pet-name").textContent = pet.name;
  document.getElementById("tick-interval").textContent = tick;

  const hungerFill = 100 - pet.hunger; 
  setBar(document.getElementById("bar-hunger"), hungerFill, true);
  document.getElementById("num-hunger").textContent = pet.hunger;

  setBar(document.getElementById("bar-happiness"), pet.happiness, true);
  document.getElementById("num-happiness").textContent = pet.happiness;

  setBar(document.getElementById("bar-hygiene"), pet.hygiene, true);
  document.getElementById("num-hygiene").textContent = pet.hygiene;

  document.getElementById("num-age").textContent = pet.age;
  const alive = !!pet.alive;
  const aliveLabel = document.getElementById("alive-label");
  aliveLabel.textContent = alive ? "살아있음" : "사망";
  aliveLabel.style.color = alive ? "var(--muted)" : "var(--bad)";

  toggleFlag(pet.age >= 10);

  const scoopBtn = document.getElementById("scoop");
  const petBtn = document.getElementById("pet");
  if (scoopBtn) {
    if (alive && extras.poop_count > 0) {
      scoopBtn.style.display = "";
      scoopBtn.textContent = `치우기 (x${extras.poop_count})`;
      scoopBtn.disabled = false;
    } else {
      scoopBtn.style.display = "none";
      scoopBtn.disabled = true;
    }
  }
  if (petBtn) {
    if (alive && extras.pet_request_active) {
      const sec = Math.ceil(extras.pet_request_remaining || 0);
      petBtn.style.display = "";
      petBtn.textContent = sec > 0 ? `쓰다듬기 (${sec}s)` : "쓰다듬기 (늦음!)";
      petBtn.disabled = false;
    } else {
      petBtn.style.display = "none";
      petBtn.disabled = true;
    }
  }

  setWalkDuration(mapRange(pet.happiness, 0, 100, 1.8, 0.9));

  const statusEl = document.getElementById("status-text");
  if (statusEl) statusEl.textContent = computeStatus(pet, extras);

  if (Array.isArray(extras.poops)) renderPoops(extras.poops);

  if (alive && extras.pet_request_active) {
    stopCharacterMovement();
    startJumping();
  } else {
    stopJumping();
    if (alive) ensureMovementRunning();
  }

  if (!alive) {
    stopCharacterMovement();
    stopJumping();
    disableAllInteractions(true);
  } else {
    disableAllInteractions(false);
  }
}

function toggleOnboarding(show) {
  const ob = document.getElementById("onboarding");
  const mainCard = document.querySelector("main.card");
  const scene = document.querySelector(".scene");
  if (!ob || !mainCard || !scene) return;
  if (show) {
    ob.classList.remove("hidden");
    mainCard.style.display = "none";
    scene.style.display = "none";
  } else {
    ob.classList.add("hidden");
    mainCard.style.display = "";
    scene.style.display = "";
  }
}

let roomEl, charEl, roomRect, charRect;
let moveTimer = null;
let currentX = 8, currentY = 8;

function mapRange(v, inMin, inMax, outMin, outMax) {
  const t = (v - inMin) / (inMax - inMin);
  return outMin + Math.max(0, Math.min(1, t)) * (outMax - outMin);
}

function setWalkDuration(sec) {
  if (!charEl) return;
  charEl.style.setProperty("--walk-dur", `${sec}s`);
}

function measureRects() {
  roomRect = roomEl.getBoundingClientRect();
  charRect = charEl.getBoundingClientRect();
}

function moveTo(x, y) {
  const goingLeft = x < currentX;
  charEl.classList.toggle("flip", goingLeft);

  const isFlipped = charEl.classList.contains("flip");
  charEl.style.setProperty("--flip", isFlipped ? "scaleX(-1)" : "none");

  currentX = x;
  currentY = y;
  charEl.style.left = `${Math.round(x)}px`;
  charEl.style.top  = `${Math.round(y)}px`;
}

function randomTarget() {
  const pad = 6;
  const maxX = roomEl.clientWidth  - charEl.clientWidth  - pad;
  const maxY = roomEl.clientHeight - charEl.clientHeight - pad;
  const x = pad + Math.random() * Math.max(0, maxX - pad);
  const y = pad + Math.random() * Math.max(0, maxY - pad);
  return { x, y };
}

function tickWalk() {
  if (!roomEl || !charEl) return;
  const { x, y } = randomTarget();
  moveTo(x, y);
  const walkDurMs = parseFloat(getComputedStyle(charEl).getPropertyValue("--walk-dur")) * 1000 || 1200;
  const rest = 400 + Math.random() * 700;
  moveTimer = setTimeout(tickWalk, walkDurMs + rest);
}

function setupCharacterMovement() {
  roomEl = document.getElementById("room");
  charEl = document.getElementById("char");
  if (!roomEl || !charEl) return;

  measureRects();
  moveTo(currentX, currentY);

  if (!charEl.complete) {
    charEl.addEventListener("load", () => {
      measureRects(); moveTo(currentX, currentY);
    }, { once: true });
  }

  window.addEventListener("resize", () => {
    measureRects();
    const pad = 6;
    const x = Math.min(Math.max(currentX, pad), roomEl.clientWidth  - charEl.clientWidth  - pad);
    const y = Math.min(Math.max(currentY, pad), roomEl.clientHeight - charEl.clientHeight - pad);
    moveTo(x, y);
  });

  if (moveTimer) clearTimeout(moveTimer);
  moveTimer = setTimeout(tickWalk, 400);
}

function ensureMovementRunning() {
  if (!moveTimer) {
    moveTimer = setTimeout(tickWalk, 400);
  }
}

function stopCharacterMovement() {
  if (moveTimer) {
    clearTimeout(moveTimer);
    moveTimer = null;
  }
}

function startJumping() {
  if (!charEl) return;
  charEl.classList.add("jump");
}
function stopJumping() {
  if (!charEl) return;
  charEl.classList.remove("jump");
}

async function refresh() {
  try {
    const data = await getState();
    const {
      ok, pet, tick_interval, name_set,
      poops, poop_count, pet_request_active, pet_request_remaining
    } = data;

    document.getElementById("api-status").textContent = ok ? "OK" : "ERR";
    toggleOnboarding(!name_set);
    if (!name_set) return;

    const extras = {
      poops,
      poop_count,
      pet_request_active,
      pet_request_remaining
    };
    updateUI(pet, tick_interval, extras);

    if (!pet.alive) {
      stopCharacterMovement();
      stopJumping();
    }
  } catch (e) {
    document.getElementById("api-status").textContent = "ERR";
    console.error(e);
  }
}

async function main() {
  const initBtn = document.getElementById("init-confirm");
  if (initBtn) {
    initBtn.addEventListener("click", async () => {
      const v = document.getElementById("init-name").value.trim();
      if (!v) return;
      await initName(v);
      await refresh();
      setupCharacterMovement();
    });
  }

  document.getElementById("feed").addEventListener("click", async () => {
    if (document.getElementById("alive-label").textContent !== "살아있음") return;
    await doAction("feed"); await refresh();
  });
  document.getElementById("play").addEventListener("click", async () => {
    if (document.getElementById("alive-label").textContent !== "살아있음") return;
    await doAction("play"); await refresh();
  });
  document.getElementById("clean").addEventListener("click", async () => {
    if (document.getElementById("alive-label").textContent !== "살아있음") return;
    await doAction("clean"); await refresh();
  });
  document.getElementById("reset").addEventListener("click", async () => {
    await resetGame();
    toggleFlag(false);          
    disableAllInteractions(false);
    await refresh();
    setupCharacterMovement();
  });

  document.getElementById("scoop").addEventListener("click", async () => {
    if (document.getElementById("alive-label").textContent !== "살아있음") return;
    await doAction("scoop"); await refresh();
  });
  document.getElementById("pet").addEventListener("click", async () => {
    if (document.getElementById("alive-label").textContent !== "살아있음") return;
    await doAction("pet"); await refresh(); 
  });

  await refresh();
  setInterval(refresh, 3000);

  const onboardingHidden = document.getElementById("onboarding").classList.contains("hidden");
  if (onboardingHidden) setupCharacterMovement();
}

document.addEventListener("DOMContentLoaded", main);
