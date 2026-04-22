// PhishTrain front-end — vanilla JS, no build step.

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

// ----- tab routing -----
$$(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    const view = btn.dataset.view;
    $$(".tab").forEach((t) => t.classList.toggle("active", t === btn));
    $$(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${view}`));
    if (view === "history") loadHistory();
  });
});

// ----- sample loading -----
async function loadSamples() {
  try {
    const r = await fetch("/api/samples");
    const samples = await r.json();
    const select = $("#sample-select");
    for (const s of samples) {
      const opt = document.createElement("option");
      opt.value = s.name;
      opt.textContent = s.label;
      select.appendChild(opt);
    }
  } catch {}
}
$("#sample-select").addEventListener("change", async (e) => {
  if (!e.target.value) return;
  const r = await fetch(`/api/samples/${encodeURIComponent(e.target.value)}`);
  const data = await r.json();
  $("#email-input").value = data.content;
});

// ----- analyze -----
$("#clear-btn").addEventListener("click", () => {
  $("#email-input").value = "";
  $("#sample-select").value = "";
  $("#result").classList.add("hidden");
});

$("#analyze-btn").addEventListener("click", async () => {
  const raw = $("#email-input").value.trim();
  if (!raw) {
    $("#analyze-status").textContent = "Paste an email first.";
    return;
  }
  $("#analyze-btn").disabled = true;
  $("#analyze-status").textContent = "Analyzing with Claude...";
  try {
    const r = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ raw_email: raw }),
    });
    if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
    const data = await r.json();
    renderResult(data);
    $("#analyze-status").textContent = "";
  } catch (e) {
    $("#analyze-status").textContent = "Error: " + e.message;
  } finally {
    $("#analyze-btn").disabled = false;
  }
});

function renderResult(data) {
  const { headers, analysis } = data;
  const result = $("#result");

  // Verdict badge
  const badge = $("#verdict-badge");
  badge.className = `badge ${analysis.verdict}`;
  badge.textContent = analysis.verdict.replace("_", " ");

  // Score bar
  $("#score-fill").style.width = analysis.score + "%";
  $("#score-value").textContent = analysis.score + " / 100";

  // Summary
  $("#summary").textContent = analysis.summary;

  // Headers
  const hb = $("#headers-block");
  const bits = [];
  if (headers.sender) bits.push(`<div><span class="k">From:</span> ${esc(headers.sender)}</div>`);
  if (headers.reply_to) {
    const mismatch = headers.sender && !sameDomain(headers.sender, headers.reply_to);
    bits.push(
      `<div><span class="k">Reply-To:</span> <span class="${mismatch ? "bad" : ""}">${esc(headers.reply_to)}</span>` +
      (mismatch ? " ← mismatch!" : "") + `</div>`
    );
  }
  if (headers.subject) bits.push(`<div><span class="k">Subject:</span> ${esc(headers.subject)}</div>`);
  if (headers.date) bits.push(`<div><span class="k">Date:</span> ${esc(headers.date)}</div>`);
  if (headers.links && headers.links.length) {
    const links = headers.links.slice(0, 8).map((l) => esc(l)).join("<br>");
    bits.push(`<div class="link-list"><span class="k">Links:</span><br>${links}${headers.links.length > 8 ? `<br><em>…and ${headers.links.length - 8} more</em>` : ""}</div>`);
  }
  hb.innerHTML = bits.join("") || '<span class="muted">No headers detected.</span>';

  // Red flags
  const fl = $("#flags-list");
  fl.innerHTML = "";
  if (analysis.red_flags.length === 0) {
    fl.innerHTML = '<li class="muted">None — this email looks clean.</li>';
  } else {
    for (const f of analysis.red_flags) {
      const li = document.createElement("li");
      li.className = "flag";
      li.innerHTML =
        `<div><span class="cat">${esc(f.category)}</span></div>` +
        `<div class="ev">${esc(f.evidence)}</div>` +
        `<div class="why">${esc(f.explanation)}</div>`;
      fl.appendChild(li);
    }
  }

  // Learning points
  const ll = $("#learning-list");
  ll.innerHTML = "";
  for (const lp of analysis.learning_points) {
    const li = document.createElement("li");
    li.textContent = lp;
    ll.appendChild(li);
  }

  result.classList.remove("hidden");
  result.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ----- history -----
async function loadHistory() {
  const [histRes, statsRes] = await Promise.all([
    fetch("/api/history"),
    fetch("/api/stats"),
  ]);
  const items = await histRes.json();
  const stats = await statsRes.json();

  const row = $("#stats-row");
  row.innerHTML = "";
  row.appendChild(makeStat("Total analyzed", stats.total));
  row.appendChild(makeStat("Phishing", stats.by_verdict?.phishing || 0, "bad"));
  row.appendChild(makeStat("Suspicious", stats.by_verdict?.suspicious || 0, "warn"));
  row.appendChild(makeStat("Legitimate", stats.by_verdict?.likely_legitimate || 0, "good"));
  row.appendChild(makeStat("Avg score", stats.avg_score));

  const list = $("#history-list");
  list.innerHTML = "";
  if (items.length === 0) {
    $("#history-empty").style.display = "block";
    return;
  }
  $("#history-empty").style.display = "none";
  for (const it of items) {
    const li = document.createElement("li");
    li.className = "history-item";
    li.innerHTML =
      `<span class="pill ${it.verdict}">${it.verdict.replace("_", " ")}</span>` +
      `<span class="subj">${esc(it.subject || "(no subject)")}</span>` +
      `<span class="muted">${it.score}</span>` +
      `<span class="when">${esc(it.created_at)}</span>`;
    list.appendChild(li);
  }
}

function makeStat(label, val, variant = "") {
  const d = document.createElement("div");
  d.className = "stat" + (variant ? " " + variant : "");
  d.innerHTML = `<div class="label">${esc(label)}</div><div class="val">${esc(val)}</div>`;
  return d;
}

// ----- quiz -----
$("#quiz-new").addEventListener("click", async () => {
  $("#quiz-new").disabled = true;
  $("#quiz-status").textContent = "Generating question...";
  $("#quiz-card").classList.add("hidden");
  try {
    const r = await fetch("/api/quiz");
    if (!r.ok) throw new Error(r.statusText);
    const q = await r.json();
    renderQuiz(q);
    $("#quiz-status").textContent = "";
  } catch (e) {
    $("#quiz-status").textContent = "Error: " + e.message;
  } finally {
    $("#quiz-new").disabled = false;
  }
});

function renderQuiz(q) {
  $("#quiz-question").textContent = q.question;
  const opts = $("#quiz-options");
  opts.innerHTML = "";
  const feedback = $("#quiz-feedback");
  feedback.classList.add("hidden");

  q.options.forEach((opt, idx) => {
    const btn = document.createElement("button");
    btn.className = "quiz-option";
    btn.textContent = opt;
    btn.addEventListener("click", () => {
      $$(".quiz-option").forEach((b) => (b.disabled = true));
      if (idx === q.correct_index) {
        btn.classList.add("correct");
      } else {
        btn.classList.add("wrong");
        $$(".quiz-option")[q.correct_index].classList.add("correct");
      }
      feedback.textContent = q.explanation;
      feedback.classList.remove("hidden");
    });
    opts.appendChild(btn);
  });
  $("#quiz-card").classList.remove("hidden");
}

// ----- helpers -----
function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function sameDomain(a, b) {
  const rx = /@([A-Za-z0-9.\-]+)/;
  const da = (a.match(rx) || [])[1]?.toLowerCase();
  const db = (b.match(rx) || [])[1]?.toLowerCase();
  return da && db && da === db;
}

loadSamples();
