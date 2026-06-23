/* ════════════════════════════════════════════════════════════
   CYBERSHIELD: ANALYST EDITION
   FILE: gamification_alevel.js
   ROLE: Grades, trophies, and end-of-session results screen
   Theme: Security Operations Centre analyst progression
   ════════════════════════════════════════════════════════════ */

// ── ANALYST GRADE THRESHOLDS ──────────────────────────────────
var GRADES = [
  { min:0,    rank:'TRAINEE ANALYST',      tag:'TA',  stars:1, colour:'#4dc8ff', glow:'rgba(77,200,255,.5)'  },
  { min:120,  rank:'JUNIOR ANALYST',       tag:'JA',  stars:2, colour:'#00ff99', glow:'rgba(0,255,153,.5)'   },
  { min:280,  rank:'SECURITY ANALYST',     tag:'SA',  stars:3, colour:'#00ff41', glow:'rgba(0,255,65,.55)'   },
  { min:480,  rank:'SENIOR ANALYST',       tag:'SrA', stars:4, colour:'#ffdd00', glow:'rgba(255,220,0,.55)'  },
  { min:700,  rank:'LEAD ANALYST',         tag:'LA',  stars:5, colour:'#ffaa00', glow:'rgba(255,170,0,.6)'   },
  { min:960,  rank:'PRINCIPAL ANALYST',    tag:'PA',  stars:6, colour:'#ff5af5', glow:'rgba(255,90,245,.6)'  },
];

function getGrade(xp){
  let g=GRADES[0];
  for(const gr of GRADES){ if(xp>=gr.min) g=gr; }
  return g;
}

// ── TROPHIES ──────────────────────────────────────────────────
var TROPHIES = [
  { id:'first_case',   icon:'🎯', name:'First Case',          desc:'Complete your first incident response mission.' },
  { id:'phish_spotter',icon:'🎣', name:'Phish Spotter',       desc:'Correctly identify and report a phishing email.' },
  { id:'trace_hero',   icon:'🌍', name:'Trace Hero',          desc:'Complete the IP trace without a single wrong answer.' },
  { id:'perfect_round',icon:'⭐', name:'Perfect Analysis',    desc:'Every decision correct in a single mission.' },
  { id:'no_lives_lost',icon:'🛡️', name:'Unscathed',           desc:'Complete a full session without losing a single life.' },
  { id:'sql_guardian', icon:'🔐', name:'SQL Guardian',        desc:'Correctly triage all SQL log entries, including the edge cases.' },
  { id:'crypto_auditor',icon:'🔑',name:'Crypto Auditor',      desc:'Identify all broken and weakening cryptographic configurations.' },
  { id:'net_shield',   icon:'📡', name:'Net Shield',          desc:'Correctly classify all network flows in a packet analysis mission.' },
  { id:'law_expert',   icon:'⚖️', name:'Law Expert',          desc:'Correctly classify all incidents by legislation — no wrong referrals.' },
  { id:'fw_architect', icon:'🧱', name:'Firewall Architect',  desc:'Correctly approve, escalate and reject all firewall change requests.' },
  { id:'quiz_ace',     icon:'🧠', name:'Quiz Ace',            desc:'Answer every post-mission quiz question correctly in a full session.' },
];

// ── PERSISTENT STATE (survives resets within a page load) ─────
var GAMIFICATION = {
  runNumber: 0,
  runHistory: [],
  trophiesEarned: new Set(),
  // Per-session module results — populated by recordModuleResult()
  _sessionResults: [],
};

// Called by engine after each module completes (optional hook — not required)
function recordModuleResult(modId, scenario, xpDelta){
  if(!GAMIFICATION._sessionResults) GAMIFICATION._sessionResults = [];
  GAMIFICATION._sessionResults.push({ modId, scenario, xpDelta });
}

// ── TROPHY ELIGIBILITY ────────────────────────────────────────
function checkTrophies(runData){
  const newly = [];

  function award(id){
    if(!GAMIFICATION.trophiesEarned.has(id)){
      GAMIFICATION.trophiesEarned.add(id);
      newly.push(id);
    }
  }

  // First case ever
  if(GAMIFICATION.runNumber === 1) award('first_case');

  // Phishing spotted
  if(GS.phishReported) award('phish_spotter');

  // IP trace won with no mistakes (lives lost specifically from trace = hard to track,
  // so we award if ipWon is true — trace bonus already requires correct answers)
  if(GS.ipWon) award('trace_hero');

  // No lives lost all session
  if(GS.livesLost === 0) award('no_lives_lost');

  // Perfect quiz (all correct, minimum 1 answered)
  if(GS.quizTotal > 0 && GS.quizCorrect === GS.quizTotal) award('quiz_ace');

  // Module-specific: check session results
  const results = GAMIFICATION._sessionResults || [];
  results.forEach(r => {
    const allCorrect = r.scenario && r.scenario.every(s => s.userAction === s.actionAnswer);
    if(allCorrect && r.scenario && r.scenario.length >= 4) award('perfect_round');
    if(r.modId === 'sqlInjection'    && allCorrect) award('sql_guardian');
    if(r.modId === 'encryptionAudit' && allCorrect) award('crypto_auditor');
    if(r.modId === 'packetAnalysis'  && allCorrect) award('net_shield');
    if(r.modId === 'legalCompliance' && allCorrect) award('law_expert');
    if(r.modId === 'firewallReview'  && allCorrect) award('fw_architect');
  });

  return newly;
}

// ── STAR RATING (1–6 from grade) ─────────────────────────────
function buildStars(count, colour){
  let h = '';
  for(let i = 1; i <= 6; i++){
    const on = i <= count;
    h += `<span style="font-size:22px;color:${on ? colour : 'rgba(255,255,255,.1)'};text-shadow:${on ? '0 0 10px '+colour : 'none'};">★</span>`;
  }
  return h;
}

// ── TROPHY CABINET HTML ───────────────────────────────────────
function buildTrophyCabinet(){
  let h = `<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;padding:6px 0;">`;
  TROPHIES.forEach(t => {
    const earned = GAMIFICATION.trophiesEarned.has(t.id);
    h += `<div style="background:rgba(0,255,65,${earned ? '.08' : '.02'});border:1px solid rgba(0,255,65,${earned ? '.35' : '.1'});border-radius:6px;padding:12px 10px;text-align:center;opacity:${earned ? '1' : '.35'};">
      <div style="font-size:26px;margin-bottom:6px;">${t.icon}</div>
      <div style="font-family:'Orbitron',monospace;font-size:11px;color:${earned ? '#00ff41' : 'rgba(0,255,65,.5)'};margin-bottom:4px;letter-spacing:.5px;">${t.name}</div>
      <div style="font-size:10px;color:rgba(0,255,65,.55);line-height:1.4;">${t.desc}</div>
      ${earned ? '' : '<div style="font-size:10px;color:rgba(255,255,255,.2);margin-top:4px;">LOCKED</div>'}
    </div>`;
  });
  h += `</div>`;
  return h;
}

// ── RUN HISTORY HTML ──────────────────────────────────────────
function buildRunHistory(){
  if(!GAMIFICATION.runHistory.length){
    return `<div style="color:rgba(0,255,65,.35);text-align:center;padding:20px;font-size:13px;">No previous runs this session.</div>`;
  }
  let h = '';
  [...GAMIFICATION.runHistory].reverse().forEach(run => {
    const g = getGrade(run.xp);
    h += `<div style="display:flex;align-items:center;gap:12px;padding:10px 12px;margin-bottom:6px;background:rgba(0,255,65,.04);border:1px solid rgba(0,255,65,.15);border-radius:5px;">
      <div style="font-family:'Orbitron',monospace;font-size:10px;color:rgba(0,255,65,.4);width:50px;flex-shrink:0;">RUN #${run.runNum}</div>
      <div style="font-size:10px;color:${g.colour};font-family:'Orbitron',monospace;flex:1;">${g.tag} — ${g.rank}</div>
      <div style="font-family:'Orbitron',monospace;font-size:14px;color:var(--g);">${run.xp} <span style="font-size:9px;color:rgba(0,255,65,.5);">XP</span></div>
      <div style="font-size:11px;color:rgba(0,255,65,.5);">${run.livesLost === 0 ? '🛡️ Unscathed' : '❤️ -'+run.livesLost}</div>
    </div>`;
  });
  return h;
}

// ── XP BREAKDOWN ──────────────────────────────────────────────
function buildXPBreak(){
  const results = GAMIFICATION._sessionResults || [];
  let modXP = 0;
  results.forEach(r => { if(r.xpDelta > 0) modXP += r.xpDelta; });
  // Estimate breakdown from totals — exact tracking would need engine hooks
  const quizXP = (GS.quizCorrect || 0) * 15;
  const phishXP = GS.phishReported ? 30 : 0;
  const ipXP = GS.ipWon ? 50 : 0;
  const total = GS.xp;
  const items = [];
  if(quizXP) items.push({ label:'Debrief quizzes', xp:quizXP });
  if(phishXP) items.push({ label:'Phishing email caught', xp:phishXP });
  if(ipXP) items.push({ label:'IP trace completed', xp:ipXP });
  items.push({ label:'Incident response', xp:Math.max(0, total - quizXP - phishXP - ipXP) });
  let h = `<div style="display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin:8px 0 14px;">`;
  items.filter(i => i.xp > 0).forEach(i => {
    h += `<div style="background:rgba(0,255,65,.06);border:1px solid rgba(0,255,65,.2);border-radius:4px;padding:5px 10px;font-size:11px;">
      <span style="color:rgba(0,255,65,.6);">${i.label}</span>
      <span style="color:var(--g);font-family:'Orbitron',monospace;margin-left:8px;">+${i.xp}</span>
    </div>`;
  });
  h += `</div>`;
  return h;
}

// ── NEWLY EARNED TROPHIES ─────────────────────────────────────
function buildNewTrophies(newIds){
  if(!newIds.length) return '';
  let h = `<div style="margin-top:12px;">`;
  h += `<div style="font-size:10px;letter-spacing:.15em;color:rgba(255,200,0,.7);text-align:center;margin-bottom:8px;">NEW TROPHY UNLOCKED</div>`;
  newIds.forEach(id => {
    const t = TROPHIES.find(x => x.id === id);
    if(!t) return;
    h += `<div style="display:flex;align-items:center;gap:10px;background:rgba(255,200,0,.07);border:1px solid rgba(255,200,0,.3);border-radius:5px;padding:10px 12px;margin-bottom:6px;animation:gmPop .5s ease;">
      <div style="font-size:28px;">${t.icon}</div>
      <div>
        <div style="font-family:'Orbitron',monospace;font-size:11px;color:#ffdd00;margin-bottom:3px;">${t.name}</div>
        <div style="font-size:11px;color:rgba(255,220,0,.6);">${t.desc}</div>
      </div>
    </div>`;
  });
  h += `</div>`;
  return h;
}

// ── RESULTS CONTENT ───────────────────────────────────────────
function buildResultsContent(grade, newTrophyIds){
  const qPct = GS.quizTotal > 0 ? Math.round((GS.quizCorrect / GS.quizTotal) * 100) : null;
  let h = `<div style="font-size:13px;color:rgba(0,255,65,.7);text-align:center;margin-bottom:12px;">SESSION COMPLETE — ${GS.totalRounds} INCIDENT(S) INVESTIGATED</div>`;

  // Stats row
  h += `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px;text-align:center;">`;
  h += `<div style="background:rgba(0,255,65,.06);border:1px solid rgba(0,255,65,.2);border-radius:5px;padding:10px;">
    <div style="font-family:'Orbitron',monospace;font-size:20px;color:var(--g);">${GS.xp}</div>
    <div style="font-size:9px;color:rgba(0,255,65,.5);margin-top:3px;letter-spacing:.1em;">TOTAL XP</div>
  </div>`;
  h += `<div style="background:rgba(0,255,65,.06);border:1px solid rgba(0,255,65,.2);border-radius:5px;padding:10px;">
    <div style="font-family:'Orbitron',monospace;font-size:20px;color:${GS.livesLost === 0 ? '#00ff99' : 'var(--amb)'};">${GS.livesLost === 0 ? '✓' : GS.livesLost}</div>
    <div style="font-size:9px;color:rgba(0,255,65,.5);margin-top:3px;letter-spacing:.1em;">${GS.livesLost === 0 ? 'UNSCATHED' : 'ERRORS MADE'}</div>
  </div>`;
  if(qPct !== null){
    h += `<div style="background:rgba(0,255,65,.06);border:1px solid rgba(0,255,65,.2);border-radius:5px;padding:10px;">
      <div style="font-family:'Orbitron',monospace;font-size:20px;color:${qPct >= 80 ? '#00ff99' : qPct >= 50 ? 'var(--amb)' : 'var(--red)'};">${qPct}%</div>
      <div style="font-size:9px;color:rgba(0,255,65,.5);margin-top:3px;letter-spacing:.1em;">QUIZ SCORE</div>
    </div>`;
  } else {
    h += `<div style="background:rgba(0,255,65,.06);border:1px solid rgba(0,255,65,.2);border-radius:5px;padding:10px;">
      <div style="font-family:'Orbitron',monospace;font-size:20px;color:${GS.phishReported ? '#00ff99' : 'rgba(0,255,65,.3)'};">${GS.phishReported ? '✓' : '—'}</div>
      <div style="font-size:9px;color:rgba(0,255,65,.5);margin-top:3px;letter-spacing:.1em;">PHISH CAUGHT</div>
    </div>`;
  }
  h += `</div>`;

  // XP breakdown
  h += buildXPBreak();

  // Spec coverage note
  const results = GAMIFICATION._sessionResults || [];
  if(results.length){
    const specMap = {
      packetAnalysis:'§1.3.3 Networks',encryptionAudit:'§1.3.1 Encryption',
      sqlInjection:'§1.3.2 Databases',firewallReview:'§1.3.3 Firewalls',
      legalCompliance:'§1.5.1 Legislation'
    };
    const covered = [...new Set(results.map(r => specMap[r.modId]).filter(Boolean))];
    if(covered.length){
      h += `<div style="background:rgba(0,245,255,.05);border:1px solid rgba(0,245,255,.15);border-radius:5px;padding:10px 12px;margin-bottom:12px;">
        <div style="font-size:9px;letter-spacing:.12em;color:rgba(0,245,255,.5);margin-bottom:5px;">H446 SPEC AREAS COVERED</div>
        <div style="font-size:12px;color:rgba(0,245,255,.8);">${covered.join('  ·  ')}</div>
      </div>`;
    }
  }

  // New trophies
  h += buildNewTrophies(newTrophyIds);

  return h;
}

// ── TAB SWITCHER ──────────────────────────────────────────────
function esTab(name){
  ['results','trophies','runs'].forEach(t => {
    const tab = document.getElementById('esTab_' + t);
    const cont = document.getElementById('esCont_' + t);
    if(tab)  tab.classList.toggle('on', t === name);
    if(cont) cont.style.display = t === name ? '' : 'none';
  });
}

// ── MAIN ENTRY POINT: showEndSplash() ─────────────────────────
// Called by engine.js → showEndgame()
function showEndSplash(){
  // Increment run counter and record trophy/history state
  GAMIFICATION.runNumber++;
  const grade = getGrade(GS.xp);
  const newTrophyIds = checkTrophies();

  // Store run in history
  GAMIFICATION.runHistory.push({
    runNum: GAMIFICATION.runNumber,
    xp: GS.xp,
    livesLost: GS.livesLost,
    gradeTag: grade.tag,
    quizPct: GS.quizTotal > 0 ? Math.round((GS.quizCorrect / GS.quizTotal) * 100) : null,
  });

  // ── Grade display ──
  const gEl = document.getElementById('esGrade');
  if(gEl){
    gEl.innerHTML = `
      <div style="font-family:'Orbitron',monospace;font-size:13px;color:rgba(0,255,65,.45);letter-spacing:.15em;margin-bottom:5px;">ANALYST RANK</div>
      <div style="font-family:'Orbitron',monospace;font-size:22px;font-weight:900;color:${grade.colour};text-shadow:0 0 24px ${grade.glow};letter-spacing:2px;">${grade.rank}</div>`;
  }

  // ── Run tag ──
  const rnEl = document.getElementById('esRunNum');
  if(rnEl) rnEl.textContent = 'SESSION #' + GAMIFICATION.runNumber;

  // ── XP number ──
  const xpEl = document.getElementById('esXPNum');
  if(xpEl) xpEl.textContent = GS.xp;

  // ── XP breakdown (hidden in this element) ──
  const xbEl = document.getElementById('esXPBreak');
  if(xbEl) xbEl.innerHTML = '';

  // ── Stars ──
  const stEl = document.getElementById('esStars');
  if(stEl) stEl.innerHTML = buildStars(grade.stars, grade.colour);

  // ── New trophies in header ──
  const ntEl = document.getElementById('esNewTrophies');
  if(ntEl){
    ntEl.innerHTML = newTrophyIds.length
      ? `<div style="font-size:11px;color:#ffdd00;margin-top:8px;letter-spacing:.1em;">🏆 ${newTrophyIds.length} new trophy${newTrophyIds.length > 1 ? ' unlocked' : ' unlocked'}</div>`
      : '';
  }

  // ── Tab content ──
  const resEl = document.getElementById('esCont_results');
  if(resEl) resEl.innerHTML = buildResultsContent(grade, newTrophyIds);

  const trEl = document.getElementById('esCont_trophies');
  if(trEl) trEl.innerHTML = buildTrophyCabinet();

  const runEl = document.getElementById('esCont_runs');
  if(runEl) runEl.innerHTML = buildRunHistory();

  // Show results tab first
  esTab('results');

  // Clear session results for next run
  GAMIFICATION._sessionResults = [];

  // Open the overlay
  document.getElementById('endSplash').classList.add('open');
}
