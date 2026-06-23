/* ════════════════════════════════════════════════════════════
   CYBERSHIELD: ANALYST EDITION
   FILE: chat-data_alevel.js
   ROLE: Group chat content for A-Level students (16–18)
   Language: technically precise, collegial, A-Level focused
   ════════════════════════════════════════════════════════════ */

var PERSONAS = {
  zara:   { id:'zara',   name:'Zara K.'  },
  marcus: { id:'marcus', name:'Marcus T.' },
  priya:  { id:'priya',  name:'Priya S.' },
};

// ── GENERAL GROUP CHAT ────────────────────────────────────────
var GENERAL_GROUP_CHAT = {
  welcome: [
    { persona:'zara',   msgs:['Good to have another analyst on shift. We get a steady stream of incidents here.','Welcome to the SOC. It gets busy — glad to have the backup.','New analyst! We\'ve been short-staffed. Ready to triage some incidents?','Hey — just in time. The alert queue\'s been growing all morning.'] },
    { persona:'marcus', msgs:['Welcome to the SOC. We get real incidents here — not drills.','Good to have another analyst. The queue doesn\'t get shorter on its own.','About time! We\'ve had some interesting cases today. You\'ll see.','Hey — grab a seat, we\'ve got alerts to get through.'] },
    { persona:'priya',  msgs:['Welcome. Quick context: we triage incoming security alerts, classify them, and escalate appropriately. Nothing goes untouched.','Glad you\'re here. We cover encryption, network security, databases and legislation — the full range of what a real SOC analyst works with.','Hi. Fair warning: the incidents are modelled on real breaches and cases. The knowledge that helps here also helps in exams. Exam-ready knowledge is genuinely useful here.','Good timing. We\'ve had a mix of network, crypto and legal incidents today. You\'ll see all of it.'] },
  ],
  between: [
    { persona:'zara',   msgs:['Good work on that one. Check the inbox — there\'s usually something else waiting.','Case closed. Refresh for the next one — the queue doesn\'t empty itself.'] },
    { persona:'marcus', msgs:['Solid. Next one\'s incoming — hit refresh.','That\'s how it\'s done. Inbox waiting.'] },
    { persona:'priya',  msgs:['Case complete. Refresh for the next alert — incidents arrive continuously.','Good. Check the inbox for the next case.'] },
  ],
  idle: [
    { persona:'marcus', msgs:[
      'Quiet window. Use it — hackers don\'t give you many of these 👀',
      'Quick revision: what\'s the difference between symmetric and asymmetric encryption? Worth knowing cold.',
      'Quick tip: make sure you can explain the TCP three-way handshake — SYN, SYN-ACK, ACK. It comes up in exams more than you\'d expect.',
      'Did you know: in 2016 Mirai took down Dyn DNS — basically the internet\'s directory — using IoT devices with default passwords.',
      'Fun question: why can\'t you "decrypt" a bcrypt hash? (Answer: it\'s not encryption. Spec)',
      'Staying sharp between alerts is part of the job.',
      'Quiet spell. Good time to review the CMA sections — S1, S2, S3 each have different maximum sentences.',
    ]},
    { persona:'zara', msgs:[
      'Calm before the next one. Stay focused.',
      'If you can explain parameterised queries in one sentence, you\'re ready for any SQL injection question.',
      'One to think about: what\'s the difference between a stateful and a stateless firewall?',
      'Quiet period. Good thinking time.',
      'Remember: hashing is one-way. Encryption is two-way. That distinction matters on the spec and in the real world.',
    ]},
    { persona:'priya', msgs:[
      'Low alert volume right now. Remain alert — patterns can emerge quickly.',
      'Spec reminder: requires knowledge of four pieces of legislation. CMA 1990, DPA 1998, CDPA 1988, RIPA 2000. Know all four.',
      'Quick thought: SHA-256 is a hash. AES-256 is a cipher. Both have 256 in the name. Know which is which and why.',
      'No active alerts. Running background checks.',
      'Between cases: review your DPA principles. Eight principles, each testable.',
    ]},
  ],
};

// ── GLOBAL CHAT POOLS ──────────────────────────────────────────
var GLOBAL_CHAT = {

  toolCorrect: [
    {persona:'marcus', msgs:['Right tool! ✅ Let\'s get into it.','Correct. Load the data.','That\'s the one. 🎯','Exactly right.','On target.']},
    {persona:'zara',   msgs:['Good call. Start working through the items.','Correct tool. Proceed.','That\'s it. ✓','Sharp.']},
    {persona:'priya',  msgs:['Confirmed. Load and triage.','Correct. Proceed with analysis.','Right tool.','Good.']},
  ],

  toolWrong: [
    {persona:'zara',   msgs:['Not quite — re-read the email. The incident type is your clue for tool selection.','Wrong tool. What does the email describe? Match the tool to the incident.','Check the email again — what category of threat is this?']},
    {persona:'marcus', msgs:['Wrong one! The email tells you what type of incident this is — read it again.','Not that tool. Think about what the email describes.','Have another look — the incident type maps directly to the right tool.']},
    {persona:'priya',  msgs:['Incorrect. Re-read the alert email. The incident type determines the tool.','Wrong tool for this incident type. Refer back to the email.','The email describes the incident category. Select the tool that addresses it.']},
  ],

  actionCorrect: [
    {persona:'marcus', msgs:['Yes! ✅','Correct call.','Exactly right.','Good read on that one.','Nailed it. 💪','Sharp analysis.','Clean.','Spot on.','That\'s the one.','Right call. 🎯','Well judged.','✓']},
    {persona:'zara',   msgs:['Correct. ✓','Good call.','That\'s right.','Well reasoned.','Exactly.','Good instinct.','Spot on.','Right.','Confirmed. ✓']},
    {persona:'priya',  msgs:['Confirmed. ✓','Correct.','Right call.','That checks out.','Exactly.','Good.','✓']},
  ],

  actionWrong: [
    {persona:'zara',   msgs:['Not quite. Re-examine the data — what specifically makes this escalate?','Look again. What\'s the key indicator in this item?','Check your reasoning — what does the technical detail tell you?']},
    {persona:'marcus', msgs:['Incorrect. Go back to the data. What makes this different from the ones you\'ve got right?','Not this time. Look more carefully at the technical specifics.','Wrong call. The detail is in the item — look again.']},
    {persona:'priya',  msgs:['Incorrect. Refer back to the item data — what\'s the defining characteristic?','Re-examine. What is the key technical indicator for this classification?','Wrong. The relevant detail is present — read it again carefully.']},
  ],

  allHandled: [
    {persona:'marcus', msgs:['All items assessed. Final step: report to the right team. 📋','Done! Who gets this report?','Every item handled. Now — which team picks this up?']},
    {persona:'zara',   msgs:['All handled. Now determine the correct reporting channel.','Good work through that. Final step: who handles this type of incident?','All assessed. Pick the right team for the debrief.']},
  ],

  reportCorrect: [
    {persona:'zara',   msgs:['Correct reporting channel. 🏆','Right team. Good.','Exactly right.','Confirmed. ✓']},
    {persona:'marcus', msgs:['Yes! Right team! 💪','Correct!','That\'s the one.','Good call on the escalation path.']},
  ],
  reportWrong: [
    {persona:'priya',  msgs:['Incorrect team. Consider what type of incident this was — which department has the relevant expertise?','Wrong escalation path. Think about the incident category.']},
    {persona:'zara',   msgs:['Not that team. Review the incident type — who handles this in a real organisation?','Wrong. Think: what function does the correct team serve?']},
  ],

  scenarioComplete: [
    {persona:'zara',   msgs:['Good work. Refresh the inbox for the next one.','Case documented. Next alert coming.']},
    {persona:'marcus', msgs:['On to the next! 📨','Inbox is waiting.']},
    {persona:'priya',  msgs:['Case closed. Refresh for the next alert.','Continue to the next incident.']},
  ],
};

// ── MODULE-SPECIFIC CHAT ──────────────────────────────────────
var MODULE_GROUP_CHAT = {};

// ── PACKET CAPTURE ANALYSIS ───────────────────────────────────
MODULE_GROUP_CHAT.packetAnalysis = {
  onLoad_1:[
    { persona:'priya',  msgs:['Network anomaly alert. The NIDS has flagged several flows — could be DDoS, scanning, or just elevated legitimate traffic. Focus on TCP flags and rate.','Packet capture triage. Key signatures to look for: SYN without ACK (SYN flood), sequential ports (scan), small request/huge response (amplification).'] },
    { persona:'marcus', msgs:['NIDS alert! Let\'s see what\'s in the capture. Could be a SYN flood, port scan, or something legitimate that triggered the threshold.','Packet flows incoming. Remember: rate + flags + source = the full picture. One attribute alone can mislead.'] },
  ],
  onLoad_2:[
    { persona:'zara',   msgs:['Work through each flow: rate first (is it abnormally high?), then flags (SYN without ACK?), then source behaviour (sequential ports?).','Load the Packet Capture Analyser. For each flow: is the rate consistent with legitimate use? Do the flags suggest an attack signature?'] },
    { persona:'priya',  msgs:['For each entry: compare rate against expected traffic profiles. TCP flags are the next indicator. SYN without ACK in volume = SYN flood. Spec','Remember: a single attribute isn\'t enough. A high rate of HTTPS from a known CDN is fine; the same rate with SYN-only from a single IP is an attack.'] },
  ],
  onStuck:[
    { persona:'zara',   msgs:['Look at the flags column. A legitimate TCP session needs SYN, then SYN-ACK, then ACK — the three-way handshake. Thousands of SYN with no ACK is the attack signature.'] },
    { persona:'priya',  msgs:['For UDP flows: compare request size to response size. DNS amplification uses tiny queries to elicit massive responses. That asymmetry is the attack vector.'] },
    { persona:'marcus', msgs:['Sequential destination ports at high rate = port scan. It\'s reconnaissance — the attacker is looking for open services. Nothing legitimate accesses ports 1 through 1024 in sequence.'] },
    { persona:'zara',   msgs:['Check the source IP column. "Tor exit node" in the source means the traffic is anonymised by design — often associated with attack infrastructure. That changes the risk profile.'] },
  ],
  onHalfway:[
    { persona:'priya',  msgs:['Good progress. Halfway through the capture. Remember: not every flow is an attack — distinguishing signal from noise is the core analyst skill.'] },
    { persona:'marcus', msgs:['Halfway! You\'re getting the pattern. SYN flood, amplification, port scan = the classic DDoS and reconnaissance vectors.'] },
  ],
  onActionWrong:[
    { persona:'priya',  msgs:['Reconsider. Look at both the rate AND the flags together — one without the other can give a misleading picture.','What protocol is this? Different protocols have different expected rate profiles — HTTPS at 45 pkts/sec is fine; TCP SYN at 47,000/sec is not.'] },
    { persona:'zara',   msgs:['Re-read that flow. The note explains the reasoning — what does it say about why this is or isn\'t an attack?','Check the flags column again. The TCP three-way handshake tells you a lot about whether a connection is legitimate.'] },
    { persona:'marcus', msgs:['Look at the source. A Tor exit node in the source IP field adds context — even low-rate traffic from that source warrants a different response.'] },
  ],
  onAllHandled:[
    { persona:'priya',  msgs:['All flows assessed. You\'ve just done what a real NIDS analyst does — separate attack traffic from legitimate traffic within the same capture window.','Good triage. In a real SOC, you\'d now be writing up indicators of compromise (IoCs) and feeding them back into the threat intelligence platform.'] },
    { persona:'marcus', msgs:['Every flow handled! SYN floods, amplification, port scans — all identified. That\'s your spec topics right there in the wild.'] },
  ],
};

// ── ENCRYPTION AUDIT ──────────────────────────────────────────
MODULE_GROUP_CHAT.encryptionAudit = {
  onLoad_1:[
    { persona:'priya',  msgs:['Cryptographic audit. You\'ll see a range of algorithms — some actively broken, some weakening, some current best practice. The spec distinction matters here.','Encryption audit. Remember: symmetric (shared key, AES), asymmetric (public/private pair, RSA), hashing (one-way, SHA/bcrypt). Different algorithms, different purposes, different risk levels.'] },
    { persona:'zara',   msgs:['Crypto audit time. Some of these will be immediately obvious — DES, MD5 for passwords, RC4. Others require a bit more thought.','Key insight for this one: it\'s not just the algorithm — it\'s also the use case. AES on a database is fine. AES for password storage is wrong.'] },
  ],
  onLoad_2:[
    { persona:'priya',  msgs:['For each system: identify the algorithm type (symmetric/asymmetric/hash), assess the key size, and check the use case is appropriate. All three factors matter.','Check algorithm, key size, and use case. A technically sound algorithm used incorrectly (AES for passwords) is still a problem — it\'s not a hash, so collision resistance isn\'t the right property.'] },
    { persona:'marcus', msgs:['Work through each config. Broken = replace now. Weakening = schedule. Current standard = maintain. Know which is which from the spec.','Look at when each was last updated. A 2009 DES config in 2025 is a serious finding.'] },
  ],
  onStuck:[
    { persona:'priya',  msgs:['DES uses a 56-bit key. On modern hardware, exhaustive key-search (brute force) is feasible. 56 bits means 2^56 possible keys — that sounds like a lot but isn\'t enough today. Replace with AES-256.'] },
    { persona:'zara',   msgs:['MD5 produces a 128-bit hash. The issue isn\'t the output length — it\'s that MD5 is fast and has known collision vulnerabilities. Fast hashes are bad for passwords: attackers can compute billions per second. Use bcrypt.'] },
    { persona:'marcus', msgs:['For asymmetric algorithms: key size is everything. RSA-512 can be factored in hours. RSA-1024 is below the NIST minimum. RSA-2048 is current minimum; RSA-4096 for future-proofing.'] },
    { persona:'priya',  msgs:['SHA-1 produced the "SHAttered" collision in 2017 — two different PDF files with the same SHA-1 hash. That\'s a broken collision resistance property. It\'s AMBER not RED because it\'s not trivially attacked yet, but schedule migration.'] },
  ],
  onHalfway:[
    { persona:'zara',   msgs:['Good progress. The exam question equivalent: "Explain why MD5 is no longer suitable for password storage." You\'re demonstrating it practically — rainbow tables, no salt, collision vulnerabilities.'] },
    { persona:'priya',  msgs:['Halfway through the audit. You\'re building a picture of the company\'s cryptographic posture. In the real world this would become a risk register entry.'] },
  ],
  onActionWrong:[
    { persona:'priya',  msgs:['Reconsider. Is the algorithm broken (should not be in use at all) or just weakening (still provides some security but needs planning to replace)? That\'s the RED/AMBER distinction.'] },
    { persona:'zara',   msgs:['Think about use case. AES-128 on a backup file is very different from AES-128 for password storage — the latter is the wrong algorithm entirely, not just a weak one.'] },
    { persona:'marcus', msgs:['Check the last updated field. An algorithm that was fine in 2010 may be a critical finding in 2025 — cryptographic standards evolve with computing power.'] },
  ],
  onAllHandled:[
    { persona:'priya',  msgs:['Audit complete. You\'ve just mapped the entire spec topic across real system configurations: symmetric, asymmetric, hashing — and crucially, appropriate versus inappropriate use cases.','Every system assessed. In a real audit this would generate a risk-ranked remediation roadmap. RED = immediate project, AMBER = next planning cycle, GREEN = review in 3 years.'] },
    { persona:'marcus', msgs:['Nailed the audit! DES, MD5, RC4 = gone. SHA-1, 3DES = on the schedule. AES-256-GCM, bcrypt, SHA-256 = solid. That\'s in practice.'] },
  ],
};

// ── SQL INJECTION DETECTION ───────────────────────────────────
MODULE_GROUP_CHAT.sqlInjection = {
  onLoad_1:[
    { persona:'priya',  msgs:['WAF alert. Application layer attack detected. SQL injection is still the most common web application vulnerability — OWASP Top 10, every year.','SQL injection log. Key tells: single quotes, comment sequences (--), always-true conditions (OR 1=1), UNION SELECT for data exfiltration. Know the patterns.'] },
    { persona:'marcus', msgs:['SQL injection triage! The classic: attacker crafts input that changes the query structure rather than just providing data.','WAF log incoming. Some of these will be obvious attacks; the interesting ones are the edge cases — a legitimate apostrophe in a name field looks like an injection test.'] },
  ],
  onLoad_2:[
    { persona:'zara',   msgs:['For each log entry: focus on the submitted value. Does it contain SQL metacharacters? Is there a comment sequence? A tautology? Or is it just natural user input that happens to contain a quote?','Read the submitted value carefully. Look for: quotes, double-hyphen (--), SQL keywords (UNION, SELECT, DROP, EXEC). The presence of one apostrophe alone doesn\'t confirm injection — context matters.'] },
    { persona:'priya',  msgs:['The goal: separate injection attempts from legitimate submissions. An Irish surname with an apostrophe (O\'Brien) is not an attack. "1 UNION SELECT * FROM users" very much is.','Consider the endpoint too. A payload in a product search field means something different to the same payload in a login field — different tables, different risk.'] },
  ],
  onStuck:[
    { persona:'zara',   msgs:['Ask yourself: could this input change the structure of the SQL query? A stray apostrophe in a name field might not — if the application uses parameterised queries, it\'s just a character. If it uses string concatenation, it\'s the start of an attack.'] },
    { persona:'priya',  msgs:['The -- sequence begins a SQL comment. Anything after -- is ignored by the database. So WHERE username=\'admin\'--\' AND password=\'anything\' becomes WHERE username=\'admin\' — bypassing the password check entirely.'] },
    { persona:'marcus', msgs:['UNION SELECT is the data exfiltration signature. By appending a second SELECT with the same number of columns, the attacker\'s query runs alongside the legitimate one and returns its results.'] },
    { persona:'zara',   msgs:['The HTTP response code is a clue. A 500 Internal Server Error after an unusual submission sometimes means a SQL error — which means the application might be processing the input as code, not data.'] },
  ],
  onHalfway:[
    { persona:'priya',  msgs:['Good progress. You\'re doing exactly what a real AppSec analyst does: distinguishing injection attempts from false positives. The O\'Brien edge case is the type of thing that trips up less experienced analysts.'] },
    { persona:'marcus', msgs:['Halfway. The fix — parameterised queries — would make this entire job unnecessary for these endpoints. Simple, well-understood, and the single most important fix in web application security.'] },
  ],
  onActionWrong:[
    { persona:'priya',  msgs:['Re-examine the submitted value. What SQL metacharacters are present? What could they do to the query structure? Is this attack syntax, a probe, or a legitimate character in context?'] },
    { persona:'zara',   msgs:['Look at the response code and the submitted value together. A 200 OK response to what looks like injection syntax is more concerning than a 400 Bad Request — the 400 suggests the WAF or validation caught it.'] },
    { persona:'marcus', msgs:['Think about intent and capability. A base64-encoded payload that decodes to SQL syntax is an obfuscated attack attempt — someone is trying to bypass signature detection. That\'s AMBER at minimum.'] },
  ],
  onAllHandled:[
    { persona:'priya',  msgs:['All log entries assessed. You\'ve just seen database security from the attacker\'s side: SQL syntax, injection vectors, and the edge cases that require careful analysis.','Case closed. The defence is always parameterised queries — separating SQL code from user data structurally, not just filtering special characters.'] },
    { persona:'marcus', msgs:['Every submission reviewed. DROP TABLE, UNION SELECT, OR 1=1, xp_cmdshell — you know all the signatures now. And the O\'Brien edge case: apostrophe in context isn\'t always injection. That distinction is exam-quality analysis.'] },
  ],
};

// ── FIREWALL RULE REVIEW ──────────────────────────────────────
MODULE_GROUP_CHAT.firewallReview = {
  onLoad_1:[
    { persona:'priya',  msgs:['Firewall change requests in the queue. Some are routine; at least one will be a risk. Apply the principle of least privilege: approve only what is strictly justified.','Change management review. For each rule: could this expand the attack surface unnecessarily? A single misconfigured rule is all it takes — SolarWinds 2020.'] },
    { persona:'zara',   msgs:['Rule change review. Think like an attacker: if you were trying to exfiltrate data or establish a C2 channel, which of these rules would you be hoping gets approved?','Firewall changes. The key question for each: is the proposed access the minimum necessary? If a /24 subnet would do the job, a /16 is too broad.'] },
  ],
  onLoad_2:[
    { persona:'priya',  msgs:['For each change request: assess protocol, port, direction and scope. Red flags: 0.0.0.0/0 as source/destination (entire internet), high-risk ports (22, 3389, 23), all-ports rules, or insufficient justification.','Load the Firewall Rule Manager. Start with direction (inbound from internet vs internal) and port (is this port associated with a high-risk service?). Then check the justification — is it specific?'] },
    { persona:'marcus', msgs:['Work through each request. Reject = security risk, Escalate = needs more information or tighter scoping, Approve = justified and appropriate. When in doubt, Escalate rather than Approve.','Firewall rule check time. Memorise the high-risk ports: 22 (SSH), 3389 (RDP), 23 (Telnet), 5900 (VNC). Any of those open to 0.0.0.0/0 is an immediate reject.'] },
  ],
  onStuck:[
    { persona:'priya',  msgs:['0.0.0.0/0 in the source field means "any IP on the internet" — that\'s every device globally. Even for relatively low-risk ports, that\'s an enormous attack surface. When you see it with port 22 or 3389, reject immediately.'] },
    { persona:'zara',   msgs:['Think about the DMZ architecture. Web servers belong in the DMZ and should accept inbound HTTPS from the internet — that\'s their purpose. Databases should be on the internal network and should never be directly accessible from the internet.'] },
    { persona:'marcus', msgs:['Port 3389 (RDP) exposed to the internet has been the entry point for countless ransomware attacks — WannaCry, NotPetya, and many more. This is a direct application of: network threats and firewalls.'] },
    { persona:'priya',  msgs:['For ESCALATE vs APPROVE: if the rule is technically reasonable but the justification is vague, the destination too broad, or there\'s no expiry date on a temporary rule — escalate. Approve only when it\'s both safe and clearly justified.'] },
  ],
  onHalfway:[
    { persona:'zara',   msgs:['Good progress. You\'re applying the principle of least privilege correctly — the narrowest scope that meets the business need. That\'s the right mindset in both real security work and any exam question about access control.'] },
    { persona:'priya',  msgs:['Halfway through the change requests. Remember: the goal isn\'t to block everything — the goal is to allow what\'s necessary and block everything else. Two very different postures.'] },
  ],
  onActionWrong:[
    { persona:'priya',  msgs:['Reconsider. What port and protocol is this? Who is the source? Is the justification specific and plausible? All three together determine the right action.'] },
    { persona:'zara',   msgs:['Look at the direction and scope together. Inbound from the internet is higher risk than inbound from a specific internal subnet. The /notation after an IP indicates the scope — /32 is one host, /0 is the entire internet.'] },
    { persona:'marcus', msgs:['Is this rule the minimum necessary? If the developer needs to reach one server, approving access for an entire /16 subnet (65,536 addresses) isn\'t the principle of least privilege — escalate to get it tightened.'] },
  ],
  onAllHandled:[
    { persona:'priya',  msgs:['All change requests assessed. You\'ve just applied (firewalls, proxies, network security) to real access control decisions. Every rule you rejected or escalated reduced the attack surface.','Review complete. In a real organisation, your findings would go to the Change Advisory Board with your rationale. The rejects become re-scoped requests; the approvals go live.'] },
    { persona:'marcus', msgs:['All done! SSH and RDP to the internet: rejected. All-ports outbound: rejected. Telnet: rejected. HTTPS to DMZ web server: approved. DNS to managed resolvers: approved. That\'s principle of least privilege in action.'] },
  ],
};

// ── LEGAL COMPLIANCE ──────────────────────────────────────────
MODULE_GROUP_CHAT.legalCompliance = {
  onLoad_1:[
    { persona:'priya',  msgs:['Legal incident review. Four pieces of legislation to apply: CMA 1990, DPA 1998, CDPA 1988, RIPA 2000. Know the difference between criminal offences (CMA/RIPA) and regulatory breaches (DPA).','Compliance triage. The key distinction: CMA violations go to the police. DPA violations go to the ICO. CDPA and minor policy issues are internal. Get this wrong and you\'ve either under-reported a crime or incorrectly involved the police.'] },
    { persona:'zara',   msgs:['Legal incident classification. Some of these will be obvious CMA S3 offences; some are DPA breaches; one or two will be internal matters only. The edge cases are the interesting ones.','Compliance review incoming. Reminder: under the CMA, intent does not negate culpability for S1 — "I was just investigating" is not a defence for unauthorised access.'] },
  ],
  onLoad_2:[
    { persona:'priya',  msgs:['For each incident: identify which law applies, which section or principle, and the appropriate response. RED = CMA/RIPA (police). AMBER = DPA (ICO). GREEN = policy only (internal).','Read each incident carefully. Focus on: was access authorised? Was personal data mishandled? Was communication intercepted? Each question maps to a different Act.'] },
    { persona:'marcus', msgs:['Work through each incident. CMA: was the access unauthorised? DPA: was personal data processed fairly? RIPA: were communications intercepted without authority? Those are your three key questions.','Load the Legal Reference Database. CMA S1 (unauth access), S2 (access with intent), S3 (impairment/malware). Each has different max sentences — know them.'] },
  ],
  onStuck:[
    { persona:'priya',  msgs:['CMA S3 applies when someone intentionally impairs a computer — including deploying malware, deleting data without authority, or installing a keylogger. Maximum sentence: 10 years. That\'s the most serious category.'] },
    { persona:'zara',   msgs:['DPA 1998 Principle 5: personal data shall not be kept longer than necessary for the specified purpose. Principle 7: appropriate security measures. Principle 1: fair and lawful processing. Each principle is separately enforceable by the ICO.'] },
    { persona:'marcus', msgs:['RIPA 2000 is specifically about interception — capturing the content of communications in transit. Accessing stored emails in someone\'s inbox is CMA S1; capturing emails as they travel across the network is RIPA. The distinction matters.'] },
    { persona:'priya',  msgs:['For the tricky ones: ask whether there was clear criminal intent or just poor judgement. A developer who accesses production data "to investigate a bug" without authorisation has committed CMA S1 regardless of intent — but context affects severity.'] },
  ],
  onHalfway:[
    { persona:'zara',   msgs:['Good progress. You\'re mapping incidents to legislation correctly — exactly the skill the exam tests. questions often present a scenario and ask which Act applies.'] },
    { persona:'priya',  msgs:['Halfway through. Remember the hierarchy: CMA = criminal (police). DPA = regulatory (ICO). CDPA = primarily civil/internal. RIPA = criminal interception. The appropriate response follows from the classification.'] },
  ],
  onActionWrong:[
    { persona:'priya',  msgs:['Reconsider the legislation. Is this an unauthorised access issue (CMA), a personal data issue (DPA), an interception issue (RIPA), or a software licensing issue (CDPA)? Each maps to a different authority.'] },
    { persona:'zara',   msgs:['Think about whether this is a criminal offence or a regulatory breach. Criminal = police (CMA, RIPA). Regulatory = ICO (DPA). This distinction determines the entire response pathway.'] },
    { persona:'marcus', msgs:['Check the specific section. CMA S1 (unauthorised access) has a max of 2 years. S3 (impairment — malware, deletion) has a max of 10. The section number affects the severity of the charge and therefore the correct action.'] },
  ],
  onAllHandled:[
    { persona:'priya',  msgs:['All incidents classified. You\'ve just applied real computing law to real incidents — CMA, DPA, CDPA, RIPA, and the edge cases that require careful reasoning. This is exactly how exam questions in this topic are structured.','Case complete. In a real organisation, the RED (police) referrals go to the legal team to brief law enforcement. The AMBER (ICO) referrals trigger the breach notification process. The GREEN cases go to HR.'] },
    { persona:'marcus', msgs:['Nailed it! CMA offences to police, DPA breaches to ICO, policy violations dealt with internally. The edge cases — good-faith access, own-data access — show the nuance the spec requires. That\'s in full.'] },
  ],
};

// ── PHISHING EXCEPTION CHAT — more technical language ─────────
var PHISHING_EXCEPTION_CHAT = {
  onOpened:[
    { persona:'zara',   msgs:['That was a spoofed email — the sender domain was lookalike, not the real thing. Character-level inspection before opening is the habit to build.','Opened a spoofed email. The send address was from a lookalike domain. Always verify the full domain, not just the display name — they can be completely different.','That one was a phishing attempt. The domain had a character substitution — very common attack vector. Check the full email address character by character in future.'] },
    { persona:'marcus', msgs:['Phishing caught you there. The domain was crafted to look legitimate at a glance. Check every character of the sender address before opening anything suspicious.','That was a credential phishing email. The domain had a subtle substitution — easy to miss when you\'re busy. Slow down on anything that triggers urgency or asks you to act immediately.','The domain wasn\'t what it appeared. Attackers use lookalike domains, Unicode homoglyphs, and subdomain tricks. Always check before you click.'] },
    { persona:'priya',  msgs:['Phishing — the sender domain was spoofed using a lookalike address. Verify the full domain, not the display name; the two can be completely independent.','That address was fraudulent. Display name spoofing and lookalike domains are standard phishing techniques. Verify the actual domain for every email requesting credentials or action.','The send-from address was not what it appeared. This is a common social engineering vector — verify sender identity through a separate, trusted channel before acting on any unexpected request.'] },
  ],
  onReported:[
    { persona:'marcus', msgs:['Caught it! Spoofed domain identified and reported. 🎯 That\'s exactly the right response.','Perfect — fake domain spotted and reported before opening. That\'s the correct process.','Identified and reported. Didn\'t open it — exactly right. That stops the attack before it can execute.','Brilliant catch. Lookalike domain, reported immediately. That\'s analyst-level email hygiene. 💪'] },
    { persona:'zara',   msgs:['Excellent. Spoofed sender identified and reported correctly. You checked before acting — exactly the right approach.','Correct call. Fake domain caught before opening. That instinct is what separates a security-aware user from a phishing victim.','Reported correctly. You didn\'t let urgency override your judgement — that\'s the key defence against social engineering.','Well spotted. Lookalike domain detected, reported, not opened. Textbook response. 🏆'] },
    { persona:'priya',  msgs:['Correct. Spoofed domain identified and reported per policy. ✓','Well handled. The domain was fraudulent — identified before opening, reported immediately. Exactly correct procedure.','Confirmed correct response. The sender address was not from the legitimate domain. Reporting rather than opening is always the right action when uncertain.','Excellent. Phishing identified and reported. The correct response regardless of how plausible the content appeared.'] },
  ],
};

// ── IP TRACE CHAT — technical language ───────────────────────
var IP_TRACE_CHAT = {
  onStart:[
    { persona:'marcus', msgs:['🔴 LIVE INTRUSION DETECTED — trace the attacker through each relay point!','ACTIVE INTRUSION! The attacker is routing through proxies — chase each hop before they cover their tracks!','BREACH IN PROGRESS! They\'re bouncing through proxy servers. Trace each IP before the trail goes cold.'] },
    { persona:'zara',   msgs:['Active intrusion detected. The attacker is routing through intermediate nodes — trace each hop to identify the origin.','Live breach — they\'re using a proxy chain to obscure their real IP. Trace each relay point.','Someone\'s in the network now. They\'re hopping through multiple servers in different jurisdictions — trace each one.'] },
    { persona:'priya',  msgs:['Active intrusion. Attacker is using proxy chaining to disguise their origin — a standard evasion technique. Trace each relay point to source the attack.','Live intrusion — attacker routing through multiple relay servers. This is standard operational security for sophisticated attackers. Identify each hop.'] },
  ],
  onHop:[
    { persona:'marcus', msgs:['Relay confirmed! Next hop! 🎯','Locked! Keep tracing!','Got it! They moved — stay on them!','Next node! Go! 💪','Relay identified — next!','Keep the trace going!'] },
    { persona:'zara',   msgs:['Relay confirmed. Next location.','Good. Continue the trace.','Signal acquired. Next hop.','Stay with it.','Keep tracing — don\'t lose the signal. 🌍'] },
    { persona:'priya',  msgs:['Relay confirmed. Proceed.','Next node identified.','Continue.','Signal maintained.','Trace active — next.'] },
  ],
  onExtend:[
    { persona:'zara',   msgs:['They\'ve extended the proxy chain — adding hops to shake the trace. Keep going.','Attacker has rerouted — more intermediate nodes added. Expected evasion tactic. Maintain the trace.'] },
    { persona:'marcus', msgs:['They know we\'re tracing! Added more relays! But we\'ve got the signal — keep going! 💻','Extended proxy chain detected. They\'re trying to exhaust our tracing capacity. Stay on it!'] },
  ],
  onWin:[
    { persona:'marcus', msgs:['ORIGIN LOCATED! Attack source identified and connection terminated! Outstanding work! 🏆','TRACED TO SOURCE! Every relay confirmed! The attacker has been isolated! Exceptional analysis! 🎯','FULL TRACE COMPLETE! Every hop confirmed — attacker\'s origin locked down!'] },
    { persona:'zara',   msgs:['Complete trace — origin identified and secured! Every relay confirmed. Excellent work. 🌟','Perfect trace. All relay points confirmed. Attacker connection severed. Impressive.'] },
    { persona:'priya',  msgs:['Full trace completed. All intermediate nodes confirmed, origin identified. Outstanding investigative work.','Trace complete. Every relay point confirmed, source located and isolated. Excellent.'] },
  ],
  onLose:[
    { persona:'zara',   msgs:['Close. The correct IP is shown in the panel — read every digit carefully. IP addresses differ by single characters at each hop.','Nearly there — check the displayed IP character by character. Attackers use very similar addresses specifically to confuse tracers.'] },
    { persona:'marcus', msgs:['So close! Check the numbers carefully next time — the decoy IPs differ by one digit. That\'s intentional.','You\'ll get it. Read the IP on screen vs the options methodically — don\'t rush the last hops.'] },
    { persona:'priya',  msgs:['Focus on the exact IP shown in the panel. Sophisticated attackers use near-identical relay IPs deliberately. Compare each octet methodically.','Trace lost on a near-identical IP. This is a real technique — generate confusingly similar addresses to slow responders. Methodical comparison is the answer.'] },
  ],
};

// ── SOCIAL ENGINEERING ANALYSIS ───────────────────────────────
MODULE_GROUP_CHAT.socialEngineering = {
  onLoad_1:[
    { persona:'priya',  msgs:['Social engineering triage. These attacks bypass every technical control — they target people, not systems. Focus on whether the request follows the correct process through the correct channel.','Staff reports of suspicious contacts. Some are clear attacks; some need verification; some are legitimate communications wrongly flagged. The false positives matter — we can\'t treat all unusual contact as hostile.'] },
    { persona:'zara',   msgs:['Human-factor attack triage. The key question isn\'t "is this technically possible?" — it\'s "does this request follow the right process, or does it try to bypass it?"','Social engineering reports in the queue. Remember: attackers use psychology, not exploits. Look for urgency, authority claims, secrecy requests and anything that asks someone to act outside normal procedure.'] },
  ],
  onLoad_2:[
    { persona:'marcus', msgs:['For each case: who is asking, what are they asking for, and does the channel match what the request requires? IT never asks for passwords. Finance never transfers money outside procurement. If those lines are crossed, it\'s an attack.','Work through the reports. The hardest ones are AMBER — they look almost right but something is off. Verify through a separate channel means: call the person on a number you already know, not one they gave you.'] },
    { persona:'priya',  msgs:['Two questions for each item: is the claimed identity verifiable, and does the request require bypassing normal process? Both answers being "no" or "yes, but" = escalate or block.','Load the Social Engineering Alert Triage tool. Some of these are obvious; some are clever. The spear-phishing ones use real internal information — that\'s what makes them dangerous.'] },
  ],
  onStuck:[
    { persona:'zara',   msgs:['Look at the channel and the request together. A request to transfer money or share credentials should always be verified by calling the person back on a number from your own records — not a number they provide.'] },
    { persona:'priya',  msgs:['Check the domain or source carefully. CEO fraud typically uses a lookalike domain — one or two characters different. The email reads like the CEO but the address is not from the company\'s actual domain.'] },
    { persona:'marcus', msgs:['Urgency is always a red flag in security contexts. "Act now or face consequences" is a manipulation tactic, not how legitimate business works. The more urgent the request, the more carefully you should verify it.'] },
    { persona:'zara',   msgs:['For the physical access cases: was this appointment pre-booked through the correct channel? Legitimate contractors are always expected in advance, escorted, and signed in. Anyone who turns up unannounced needing immediate server room access should be refused.'] },
  ],
  onHalfway:[
    { persona:'marcus', msgs:['Halfway through. The pattern: clear process violation = RED. Unusual but needs checking = AMBER. Follows correct procedure through correct channel = GREEN. The AMBER ones are where judgement matters.'] },
    { persona:'priya',  msgs:['Good progress. Notice the GREEN cases all have something in common: they use the right channel, they reference a known process, and they don\'t ask for anything out of the ordinary. That\'s what legitimate looks like.'] },
  ],
  onActionWrong:[
    { persona:'priya',  msgs:['Reconsider. Look at the channel and the request together. Does this request require bypassing a normal security process? That\'s the core test.','Check the sender domain or source identity. Is this genuinely from who it claims to be from, verifiable through an independent channel?'] },
    { persona:'zara',   msgs:['Think about what\'s being asked. Credentials, financial transfers, physical access to secure areas — all require verification, not just compliance. Which category does this fall into?'] },
    { persona:'marcus', msgs:['Look at the urgency and secrecy signals. "Don\'t tell anyone" and "act immediately" together are almost always manipulation tactics. Legitimate requests tolerate verification delays.'] },
  ],
  onAllHandled:[
    { persona:'priya',  msgs:['All reports triaged. You\'ve just worked through the main social engineering attack types: phishing, spear-phishing, vishing, smishing, pretexting, baiting and BEC. The universal defence — verify through a separate channel — applies to every one of them.','Case complete. In a real SOC, the RED cases would trigger staff interviews, phishing takedowns and HR investigations. The AMBER cases would generate verification workflows. This is what the human factor security team does daily.'] },
    { persona:'marcus', msgs:['Every case handled. The Twitter hack in 2020 used only phone calls — no exploits. Social engineering is often more effective than technical attacks because it targets the weakest link in any security system: the human decision to trust.'] },
  ],
};

// ── MALWARE BEHAVIOUR ANALYSIS ────────────────────────────────
MODULE_GROUP_CHAT.malwareAnalysis = {
  onLoad_1:[
    { persona:'priya',  msgs:['Endpoint detection alert. The EDR has flagged several processes for unusual behaviour. Some are active malware; some are edge cases; some are legitimate system processes that look suspicious on the surface.','Malware triage. The key insight: behaviour alone doesn\'t tell you everything — you need behaviour AND path AND network activity together. A process doing something unusual is different from a process doing something unusual from an unexpected location.'] },
    { persona:'marcus', msgs:['EDR alert! We need to triage these process behaviours. The golden rule: legitimate Windows system processes run from C:\\Windows\\System32. Anything in AppData\\Temp with the same name as a system process is spoofing that process name.','Endpoint logs incoming. Focus on three things per entry: the executable path, what it\'s doing, and who it\'s talking to on the network. Those three together tell you what you\'re dealing with.'] },
  ],
  onLoad_2:[
    { persona:'zara',   msgs:['Load the Endpoint Detection Log Viewer. For each entry: is the path legitimate for this process? Is the behaviour consistent with its claimed function? Are the network connections going where they should?','Work through each process. The hardest ones are legitimate tools (PowerShell, wscript, msiexec) being misused. The process itself is real — what it\'s doing isn\'t.'] },
    { persona:'priya',  msgs:['Remember the malware types as you go through these. Ransomware = high file write rate, new extensions. Worm = lateral spread to other hosts. Trojan = appears legitimate, has backdoor. Keylogger = keyboard API hooks, outbound exfiltration. Spyware = screen capture, file collection.','Triage each alert. Some will be obvious (ransomware encrypting files at 8,000 writes/min). Some will require checking the path against known legitimate locations.'] },
  ],
  onStuck:[
    { persona:'priya',  msgs:['Check the executable path carefully. C:\\Windows\\System32 = legitimate system location. C:\\Users\\[username]\\AppData\\Temp = not a legitimate location for any Windows system process. That distinction catches most of the name-spoofing attempts.'] },
    { persona:'zara',   msgs:['Look at the network connections column. Legitimate system processes connect to known Microsoft or vendor IP ranges. A system process making periodic connections to a random external IP on a fixed schedule is almost always a command and control (C2) connection.'] },
    { persona:'marcus', msgs:['For the GREEN cases: look for known legitimate process names in legitimate paths connecting to known legitimate destinations. MsMpEng.exe is Windows Defender. wuauclt.exe is Windows Update. VeeamAgent.exe doing high file reads during a scheduled overnight window is a backup. Context matters.'] },
    { persona:'priya',  msgs:['PowerShell with -ExecutionPolicy Bypass means "ignore the policy that requires scripts to be signed." Combined with -WindowStyle Hidden and -EncodedCommand, there is almost no legitimate use case — this is a standard malware delivery pattern.'] },
  ],
  onHalfway:[
    { persona:'marcus', msgs:['Halfway through. You\'re building pattern recognition for malware behaviour. Wrong path = spoofing. High file writes + new extensions = ransomware. SMB spread = worm. Reverse shell = RAT. Scheduled C2 = botnet. These are real detection signatures.'] },
    { persona:'priya',  msgs:['Good progress. Notice how the GREEN cases all have something in common: known process, correct path, expected behaviour for their function, known network destinations. Deviation from any of those three is the signal.'] },
  ],
  onActionWrong:[
    { persona:'priya',  msgs:['Re-examine the path. Where is this process running from? That single factor resolves most ambiguous cases — legitimate system processes don\'t run from Temp folders.','Check the network activity column. Is this process connecting somewhere it has no reason to connect? What is the destination IP, and is that consistent with what the process claims to be?'] },
    { persona:'zara',   msgs:['Think about the behaviour description. Is the activity rate consistent with legitimate use? 8,000 file writes per minute is not backup — it\'s encryption. Context changes the interpretation.'] },
    { persona:'marcus', msgs:['Look at timing. A scheduled task running a PowerShell script at 3am with hidden window and encoded command is not IT maintenance — no legitimate admin script needs those three flags together.'] },
  ],
  onAllHandled:[
    { persona:'priya',  msgs:['All processes triaged. You\'ve just worked through the main malware types — ransomware, keylogger, worm, trojan, spyware, malicious PowerShell — alongside legitimate system processes performing normal functions. Path + behaviour + network activity: those three tell the story.','Case complete. In a real IR engagement, the RED findings trigger host isolation, forensic imaging and a full incident response process. The AMBER findings go into a 24-hour watch queue. The GREENs get documented as known-good baselines.'] },
    { persona:'marcus', msgs:['Every process assessed. WannaCry (2017) hit 200,000 systems in 150 countries in a single day because it combined worm propagation with ransomware encryption. Recognising those two behaviours in EDR logs — fast lateral spread + high file write rate — is how you catch it early.'] },
  ],
};
