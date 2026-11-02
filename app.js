/* 성적 조회: 학번|이름 → PBKDF2 → (lookup tag, AES-GCM key) → 레코드 복호화 */
(function () {
  "use strict";
  const D = window.GRADE_DATA;
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const hex = (buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  const normId = (v) => String(v || "").replace(/\D/g, "");
  const normName = (v) => String(v || "").replace(/\s+/g, "");

  async function lookup(id, name) {
    const pw = enc.encode(`${normId(id)}|${normName(name)}`);
    const base = await crypto.subtle.importKey("raw", pw, "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: b64(D.salt), iterations: D.iterations }, base, 512);
    const tag = hex(bits.slice(0, 32));
    const rec = D.records.find((r) => r.k === tag);
    if (!rec) return null;
    const key = await crypto.subtle.importKey("raw", bits.slice(32, 64), "AES-GCM", false, ["decrypt"]);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(rec.iv) }, key, b64(rec.ct));
    return JSON.parse(dec.decode(pt));
  }

  const fmt = (x) => (Number.isInteger(x) ? String(x) : x.toFixed(1).replace(/\.0$/, ""));

  function renderStats() {
    const host = document.getElementById("stats");
    if (!host) return;
    host.innerHTML = Object.keys(D.stats).sort().map((sec) => {
      const s = D.stats[sec];
      return `
      <section class="card stat" aria-label="${sec}분반 통계">
        <h2>${sec}분반 <span class="muted">(${s.n}명)</span></h2>
        <dl>
          <div><dt>평균</dt><dd>${s.mean.toFixed(2)}</dd></div>
          <div><dt>중앙값</dt><dd>${fmt(s.median)}</dd></div>
          <div><dt>표준편차</dt><dd>${s.sd.toFixed(2)}</dd></div>
        </dl>
      </section>`;
    }).join("");
  }

  function renderResult(r) {
    const wrongMc = r.wrong_mc.length ? r.wrong_mc.join(", ") + "번" : "없음";
    const wrongSa = r.wrong_sa.length ? r.wrong_sa.join(", ") : "없음";
    const essay = r.essay.length === 2
      ? `${fmt(r.essay[0])} + ${fmt(r.essay[1])} = ${fmt(r.essay_total)}`
      : fmt(r.essay_total);
    return `
      <div class="result-head">
        <div>
          <div class="muted">${r.sec}분반</div>
          <div class="who">${r.name} <span class="muted">${r.id}</span></div>
        </div>
        <div class="grade-badge">${r.grade}</div>
      </div>
      <div class="total"><span class="muted">총점</span> <strong>${fmt(r.total)}</strong> <span class="muted">/ 100</span></div>
      <table class="breakdown">
        <thead><tr><th>영역</th><th>점수</th><th>틀린 문항</th></tr></thead>
        <tbody>
          <tr><td>I. 객관식 <span class="muted">(50)</span></td><td>${fmt(r.mc)}</td><td>${wrongMc}</td></tr>
          <tr><td>II. 단답형 <span class="muted">(20)</span></td><td>${fmt(r.sa)}</td><td>${wrongSa}</td></tr>
          <tr><td>III. 주관식 <span class="muted">(30)</span></td><td>${essay}</td><td class="muted">28번${r.essay.length === 2 ? " + 29번" : "·29번 합산"}</td></tr>
        </tbody>
      </table>
      <p class="note">객관식은 문항당 2점, 단답형은 빈칸당 2.5점 감점입니다. 이의가 있으면 담당 교수에게 문의하세요.</p>`;
  }

  function bind() {
    const form = document.getElementById("lookup");
    if (!form) return;
    const out = document.getElementById("result");
    const btn = form.querySelector("button");
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const id = form.elements.sid.value, name = form.elements.sname.value;
      out.className = "card result";
      if (normId(id).length < 6 || !normName(name)) {
        out.innerHTML = `<p class="err">학번과 이름을 모두 입력하세요.</p>`;
        out.hidden = false; return;
      }
      btn.disabled = true; out.hidden = false;
      out.innerHTML = `<p class="muted">조회 중…</p>`;
      try {
        const r = await lookup(id, name);
        out.innerHTML = r ? renderResult(r)
          : `<p class="err">일치하는 기록이 없습니다. 학번(숫자 8자리)과 이름(띄어쓰기 없이)을 다시 확인하세요.</p>`;
      } catch (e) {
        out.innerHTML = `<p class="err">조회 중 오류가 발생했습니다. 최신 브라우저(Chrome, Edge, Safari)에서 다시 시도하세요.</p>`;
      } finally {
        btn.disabled = false;
      }
    });
  }

  window.GradeLookup = { lookup, renderResult };
  document.addEventListener("DOMContentLoaded", () => { renderStats(); bind(); });
})();
