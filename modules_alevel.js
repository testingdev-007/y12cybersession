/* ════════════════════════════════════════════════════════════
   CYBERSHIELD: ANALYST EDITION
   FILE: modules_alevel.js
   ROLE: Simulation content for A-Level students (16-18)
   SPEC: OCR A-Level Computer Science H446 v3.0
   ════════════════════════════════════════════════════════════

   Modules and spec coverage:
   1. packetAnalysis  — H446 §1.3.3  Networks, TCP/IP, firewalls
   2. encryptionAudit — H446 §1.3.1  Encryption & Hashing
   3. sqlInjection    — H446 §1.3.2  Databases & SQL
   4. firewallReview  — H446 §1.3.3  Firewalls & proxies
   5. legalCompliance — H446 §1.5.1  Computing legislation

   Accuracy checklist per scenario:
   ✓ Is this technically accurate?
   ✓ Is this in the OCR H446 spec?
   ✓ Is this positioned at A-Level standard?
   ════════════════════════════════════════════════════════════ */

var MODULES = {};

// ── Utility helpers ──────────────────────────────────────────
function randInt(min,max){return Math.floor(Math.random()*(max-min+1))+min;}
function randFloat(min,max,dp=1){return parseFloat((Math.random()*(max-min)+min).toFixed(dp));}
function pick(arr){return arr[Math.floor(Math.random()*arr.length)];}
function shuffle(arr){const a=[...arr];for(let i=a.length-1;i>0;i--){const j=Math.floor(Math.random()*(i+1));[a[i],a[j]]=[a[j],a[i]];}return a;}
function jitter(base,pct=0.15){return Math.round(base*(1+(Math.random()-0.5)*pct*2));}
function _pickPool(pool,numR,numA,numG){
  const reds=shuffle(pool.filter(p=>p.ragAnswer==='R'));
  const ambs=shuffle(pool.filter(p=>p.ragAnswer==='A'));
  const grns=shuffle(pool.filter(p=>p.ragAnswer==='G'));
  const r=Math.min(numR,reds.length);
  const a=Math.min(numA,ambs.length);
  const g=Math.min(numG,grns.length);
  return shuffle([...reds.slice(0,r),...ambs.slice(0,a),...grns.slice(0,g)])
    .map(item=>({...item,handled:false,userRag:null,userAction:null}));
}

// ═══════════════════════════════════════════════════════════
// MODULE 1: NETWORK PACKET CAPTURE ANALYSIS
// H446 §1.3.3 — Networks, TCP/IP stack, security threats,
// firewalls, proxies, packet switching, DDoS
// ═══════════════════════════════════════════════════════════
MODULES.packetAnalysis = {
  id: 'packetAnalysis',
  name: 'PACKET CAPTURE ANALYSIS',

  emailSender: ()=>pick(['nids@secops.internal','siem-alerts@infrasec.net','noc@threatwatch.io','soc@cyberdefence.net']),
  emailSubject: ()=>pick(['NIDS Alert: Anomalous Traffic Pattern Detected','SIEM P1 Alert: Network Anomaly Requires Triage','Packet Capture Review — Analyst Action Required','NOC Alert: Suspicious Traffic Flows']),
  emailBody(){
    return pick([
      `Analyst,\n\nThe NIDS has raised a P1 alert for anomalous network behaviour in the last 15 minutes. Several traffic flows require urgent triage.\n\nLoad the Packet Capture Analyser and classify each flow. Consider: packet rate, TCP flags, source behaviour and whether the pattern matches a known attack signature.\n\nNote: not all flows are malicious. Distinguish signal from noise.\n\nSecurity Operations Centre`,
      `Hi,\n\nOur SIEM has correlated multiple alerts. A number of network flows look unusual — some may be attacks, others may be legitimate traffic coincidentally elevated.\n\nUse the Packet Capture Analyser to triage each flow. Focus on protocol, flags, rate and source reputation.\n\nCyber Defence Team`,
      `Analyst,\n\nMultiple anomalous flows detected in the last capture window. This could range from active DDoS to routine scanning. Your triage determines our response.\n\nKey questions for each flow: Does the rate fit an attack profile? Do the TCP flags suggest a well-known attack vector? Is the source on any threat intelligence feeds?\n\nNOC`
    ]);
  },

  tools: {
    correct: 'Packet Capture Analyser',
    decoys: ['Encryption Audit Tool','SQL Query Log Viewer','Firewall Rule Manager','Legal Reference Database','Vulnerability Scanner','DNS Lookup Tool','Certificate Checker']
  },

  briefing: {
    title: 'Network Packet Capture Analysis',
    tagline: 'Triaging raw network flows for known attack signatures',
    summary: 'Every network communication is broken into packets: discrete units with a header (source IP, destination IP, protocol, port, flags) and payload. A Network Intrusion Detection System (NIDS) logs these flows. Key indicators: TCP SYN without ACK (SYN flood), sequential port increments (port scan), small queries generating large responses (amplification). Understanding the TCP three-way handshake (SYN → SYN-ACK → ACK) and what each flag signals is essential for distinguishing attacks from legitimate traffic.',
    watchFor: 'Very high packet rate from a single source IP • SYN flag set without corresponding ACK responses • Sequential destination port numbers (reconnaissance scan) • Asymmetric request/response sizes (amplification vector) • Source IPs on threat intelligence blocklists or Tor exit node registries • Internal hosts initiating unusual outbound high-volume connections',
    realWorld: 'In September 2016 the Mirai botnet, comprising 100,000+ compromised IoT devices, attacked DNS provider Dyn at 1.2 Tbps using SYN floods and UDP amplification — taking Twitter, Reddit and Netflix offline for hours. The same botnet had previously attacked journalist Brian Krebs at 620 Gbps. Both attacks exploited default credentials on cameras and DVRs.'
  },

  generateScenario({numItems=6}={}){
    const pool = [
      // RED — clear attack signatures
      {
        name:'FLOW-A1', purpose:'TCP traffic from single external host',
        srcIP:'45.92.14.7', protocol:'TCP', dstPort:'80', rate:'47,200 pkts/sec', flags:'SYN (no ACK)',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Classic SYN flood: tens of thousands of SYN packets/sec from one IP with no ACK responses. The server exhausts its half-open connection table. Block at perimeter firewall immediately..'
      },
      {
        name:'FLOW-A2', purpose:'UDP traffic — DNS amplification vector',
        srcIP:'203.0.113.50', protocol:'UDP', dstPort:'53', rate:'8,400 pkts/sec', flags:'N/A',
        ragAnswer:'R', actionAnswer:'block',
        notes:'DNS amplification: 14-byte queries eliciting 3,800-byte responses — a 271× amplification factor. A botnet sends spoofed queries using the victim\'s IP as source; the DNS server unknowingly floods the victim..'
      },
      {
        name:'FLOW-A3', purpose:'TCP traffic — sequential port targeting',
        srcIP:'91.108.4.128', protocol:'TCP', dstPort:'1–1024 (sequential)', rate:'2,100 pkts/sec', flags:'SYN',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Sequential port scan: attacker probing ports 1–1024 looking for open services. This is reconnaissance before an attack. SYN-only packets to each port in sequence is the signature. Block source and log for threat intelligence.'
      },
      {
        name:'FLOW-A4', purpose:'ICMP flood from external source',
        srcIP:'198.51.100.42', protocol:'ICMP', dstPort:'N/A', rate:'32,000 pkts/sec', flags:'Echo Request (type 8)',
        ragAnswer:'R', actionAnswer:'block',
        notes:'ICMP flood (Ping flood): oversized 1,472-byte echo requests at 32,000/sec from one source. A volumetric DDoS attack designed to saturate bandwidth. ICMP at this rate has no legitimate justification.'
      },
      {
        name:'FLOW-A5', purpose:'TCP — many partial connections',
        srcIP:'5.188.206.14', protocol:'TCP', dstPort:'80', rate:'18,000 partial conns', flags:'SYN only (never completed)',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Slowloris-style attack: thousands of HTTP connections opened simultaneously, each never completed. This exhausts the web server\'s connection pool without flooding bandwidth. Low-and-slow but devastating to application servers.'
      },
      // AMBER — suspicious, needs investigation
      {
        name:'FLOW-B1', purpose:'SSH traffic from Tor exit node',
        srcIP:'185.220.101.5 (Tor exit)', protocol:'TCP', dstPort:'22', rate:'3 pkts/sec', flags:'SYN, ACK',
        ragAnswer:'A', actionAnswer:'monitor',
        notes:'Low-and-slow SSH authentication attempts from a known Tor exit node. Rate is deliberately low to evade rate-based detection. Source IP confirmed on multiple threat intelligence blocklists. Monitor for credential stuffing. SSH (port 22) is a high-value target.'
      },
      {
        name:'FLOW-B2', purpose:'HTTPS from unexpected geolocation',
        srcIP:'119.29.57.221 (CN)', protocol:'HTTPS', dstPort:'443', rate:'180 pkts/sec', flags:'SYN, ACK, PSH',
        ragAnswer:'A', actionAnswer:'monitor',
        notes:'Consistent HTTPS traffic from an IP geolocating to China. Rate is not alarming but is unusual — the company has no commercial presence in this region. May warrant geoblocking or closer inspection of exfiltrated payload volume. Monitor for data exfiltration patterns.'
      },
      {
        name:'FLOW-B3', purpose:'SMB traffic from internal workstation',
        srcIP:'10.0.14.52 (internal)', protocol:'TCP', dstPort:'445', rate:'850 conns/sec', flags:'SYN, ACK',
        ragAnswer:'A', actionAnswer:'monitor',
        notes:'Unusually high SMB (port 445) connection attempts originating from an internal host. Could indicate worm propagation or lateral movement following a compromise. The internal source makes this AMBER rather than RED — investigate the source host.'
      },
      // GREEN — normal, legitimate traffic
      {
        name:'FLOW-C1', purpose:'Standard HTTPS web traffic',
        srcIP:'147.161.30.5', protocol:'HTTPS', dstPort:'443', rate:'45 pkts/sec', flags:'SYN, ACK, PSH, FIN',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Normal HTTPS browsing traffic. Packet rate, size distribution (800–1500 bytes variable) and flag sequence are all consistent with a TLS session from a legitimate browser.'
      },
      {
        name:'FLOW-C2', purpose:'DNS resolution to public resolver',
        srcIP:'8.8.8.8', protocol:'UDP', dstPort:'53', rate:'12 pkts/sec', flags:'N/A',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Standard DNS resolution traffic to Google public DNS (8.8.8.8). Query/response sizes and rate are consistent with normal client-side domain lookups. No amplification pattern detected.'
      },
      {
        name:'FLOW-C3', purpose:'NTP time synchronisation',
        srcIP:'pool.ntp.org', protocol:'UDP', dstPort:'123', rate:'1 pkt/min', flags:'N/A',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'NTP (Network Time Protocol) clock synchronisation. Standard 48-byte packets at expected intervals of roughly once per minute. Normal operating system behaviour on all networked hosts.'
      },
      {
        name:'FLOW-C4', purpose:'SMTP relay from internal mail server',
        srcIP:'192.168.1.10 (mail.internal)', protocol:'TCP', dstPort:'25', rate:'8 pkts/sec', flags:'SYN, ACK',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Standard SMTP email delivery from the internal mail relay. Volume and pattern are consistent with normal business email activity during working hours. Source is a known internal mail server.'
      },
    ];
    const nR=pick([1,1,2,2,3]);
    const nA=pick([0,1,1,2]);
    const nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Network Security Operations Centre (NSOC)', incorrect:'Human Resources Department' },
  reportHint: 'Packet-level attacks require network-layer containment — which team owns the network perimeter?',

  completionText(_,sc){
    const att=sc.filter(s=>s.ragAnswer!=='G').length;
    return `<div class="rc info"><h3>PACKET ANALYSIS — KEY PRINCIPLES</h3>
    <p>${att} suspicious flow(s) identified. When triaging captures: <strong>rate</strong> (abnormally high?), <strong>flags</strong> (SYN without ACK = SYN flood), <strong>pattern</strong> (sequential ports = scan), <strong>asymmetry</strong> (small request/huge response = amplification).</p>
    <p style="margin-top:8px;"><strong>Key concepts:</strong> TCP three-way handshake (SYN→SYN-ACK→ACK), DNS over UDP, packet switching, stateful firewalls, proxy servers, DDoS attack types.</p></div>`;
  },

  actions:{ R:'block', A:'monitor', G:'allow' },
  actionLabels:{ block:'🚫 BLOCK SOURCE', monitor:'👁 MONITOR & ALERT', allow:'✅ ALLOW FLOW' },
  ragRules:{
    R:'Clear attack signature: SYN flood / scan / amplification → BLOCK SOURCE',
    A:'Suspicious: unusual source, low-and-slow, unexpected geo → FLAG & MONITOR',
    G:'Normal traffic profile: expected protocol, rate, source → ALLOW',
  },

  plenary:{
    reportHint: 'Packet-level attacks require network-layer containment — which team owns the network perimeter?',
    analogy: 'Triaging packet captures is like reviewing airport security footage: most passengers are legitimate, but specific behavioural patterns — trying every gate, sending thousands of identical bags, or arriving from unusual routes — stand out once you know the signatures.',
    whatHappened: 'The network was being probed and attacked simultaneously: a volumetric SYN flood, a DNS amplification attack, and a reconnaissance port scan — all occurring against a backdrop of entirely normal traffic that required careful distinction.',
    keyMove: 'SYN only, no ACK, high rate = SYN flood (RED). Small request → huge response = amplification (RED). Sequential ports = scan (RED). Low-rate SSH from Tor exit node = suspicious (AMBER). Expected protocol, rate and source = allow (GREEN).',
    realWorld: 'The 2016 Mirai botnet attack on Dyn demonstrated that IoT devices with default credentials could generate record-breaking traffic. Understanding TCP flags, DNS amplification, and DDoS anatomy is essential for any network security analyst.',
    quiz:[
      {q:'A capture shows 50,000 TCP packets per second from one IP, all with SYN=1 ACK=0. This is most characteristic of:',options:['Normal high-traffic web browsing','A SYN flood DDoS attack','A legitimate DNS zone transfer'],correct:1},
      {q:'DNS primarily uses which transport protocol, and why?',options:['TCP — to guarantee reliable delivery of zone transfers and large queries','UDP — for low-overhead, fast queries where a lost packet just triggers a retry','HTTPS — to encrypt all DNS lookups from eavesdropping'],correct:1},
      {q:'In packet switching (unlike circuit switching), packets:',options:['Follow a single reserved end-to-end circuit for the session','May take different routes and are reassembled at the destination','Are broadcast to all nodes simultaneously on the network'],correct:1},
      {q:'A proxy server deployed in a corporate network can:',options:['Encrypt all files stored on the internal file server','Filter and log outbound web requests on behalf of internal clients, hiding their IPs','Replace the routing function of the default gateway'],correct:1},
      {q:'Which of the following is NOT a typical characteristic of a DDoS attack?',options:['Traffic originates from many distributed source IP addresses','The target service becomes unavailable to legitimate users','All attack traffic originates from a single source IP address'],correct:2},
      {q:'A botnet is best described as:',options:['An automated network vulnerability scanner used by security teams','A collection of compromised hosts controlled remotely to carry out coordinated attacks','A type of stateful firewall that blocks known malicious traffic'],correct:1},
      {q:'UDP differs from TCP in that it:',options:['Guarantees reliable, ordered delivery via acknowledgement numbers','Is faster but provides no delivery guarantees, ordering or flow control','Requires a three-way handshake before any data transfer can begin'],correct:1},
      {q:'The TCP three-way handshake sequence is:',options:['ACK → SYN → SYN-ACK (client confirms, server accepts, client acknowledges)','SYN → SYN-ACK → ACK (client requests, server responds, client confirms)','SYN → ACK → FIN (connect, confirm, terminate)'],correct:1},
      {q:'A stateful firewall differs from a stateless packet filter because it:',options:['Only examines source/destination IP addresses and port numbers in the header','Tracks the state of network connections and allows returning traffic for established sessions','Blocks all traffic by default and requires explicit allow rules for every packet'],correct:1},
    ]
  }
};


// ═══════════════════════════════════════════════════════════
// MODULE 2: ENCRYPTION CONFIGURATION AUDIT
// H446 §1.3.1 — Symmetric & asymmetric encryption, hashing
// ═══════════════════════════════════════════════════════════
MODULES.encryptionAudit = {
  id: 'encryptionAudit',
  name: 'ENCRYPTION CONFIGURATION AUDIT',

  emailSender: ()=>pick(['crypto@secops.internal','key-mgmt@infrasec.net','audit@cryptoteam.io','ciso-office@company.net']),
  emailSubject: ()=>pick(['Cryptographic Audit: Immediate Action Required','Quarterly Encryption Review — Critical Findings','CISO Request: Encryption Health Check','Cryptography Audit Report — Analyst Review Needed']),
  emailBody(){
    return pick([
      `Analyst,\n\nOur quarterly cryptographic audit has flagged several systems using outdated or broken algorithms. Some represent an immediate risk; others need scheduling for replacement.\n\nLoad the Encryption Audit Tool. For each system, determine whether the algorithm and key size are still fit for purpose: RED (replace urgently), AMBER (schedule replacement), or GREEN (maintain).\n\nCryptography Team`,
      `Hi,\n\nFollowing the latest NIST deprecation guidance, we need to audit all encryption across our systems. Some algorithms are now considered cryptographically broken; others are weakening but not yet critical.\n\nUse the Encryption Audit Tool to classify each configuration. Consider algorithm strength, key size and appropriate use case.\n\nKey Management Team`,
      `Analyst,\n\nWe've had a tip-off that a competitor's breach was linked to weak hashing on their password store. We need to verify our own cryptographic posture before this becomes an issue.\n\nReview each system using the Encryption Audit Tool. Pay particular attention to whether hashing algorithms are being used correctly — a fast hash is not appropriate for passwords.\n\nCISO Office`
    ]);
  },

  tools: {
    correct: 'Encryption Audit Tool',
    decoys: ['Packet Capture Analyser','SQL Query Log Viewer','Firewall Rule Manager','Legal Reference Database','Network Traffic Monitor','Process Monitor','Certificate Transparency Log']
  },

  briefing: {
    title: 'Encryption Configuration Audit',
    tagline: 'Assessing cryptographic algorithm strength across all company systems',
    summary: 'Encryption protects data in transit and at rest. Symmetric algorithms (AES, DES) use one shared key for both encryption and decryption. Asymmetric algorithms (RSA) use mathematically linked public/private key pairs — encrypt with the recipient\'s public key, decrypt with their private key. Hashing (SHA-256, MD5) is a one-way process producing a fixed-length digest — it cannot be reversed. As computing power increases, previously secure algorithms become vulnerable and must be replaced.',
    watchFor: 'DES-56 (56-bit key, broken — replace immediately) • MD5 or SHA-1 for password hashing (vulnerable to rainbow tables) • RC4 stream cipher (statistical biases, deprecated) • RSA keys below 2048 bits • Any cipher marked DEPRECATED by NIST or NCSC • AES used for password storage (wrong use case — should use bcrypt or Argon2)',
    realWorld: 'In 2012 LinkedIn suffered a breach in which 6.5 million password hashes were posted online. LinkedIn was using unsalted SHA-1 — a fast cryptographic hash with no salt. Attackers cracked the majority of passwords within days using precomputed rainbow tables. By 2016, a full 117 million records from the same breach were being sold. The fix: use bcrypt, scrypt or Argon2 — algorithms designed to be slow and resist precomputation.'
  },

  generateScenario({numItems=6}={}){
    const pool = [
      // RED — cryptographically broken, replace immediately
      {
        name:'db-auth-service', purpose:'DES-56 | User authentication database',
        algorithm:'DES', keySize:'56 bits', useCase:'Data at rest (authentication DB)', lastUpdated:'2009',
        ragAnswer:'R', actionAnswer:'replace',
        notes:'DES (Data Encryption Standard) with a 56-bit key is cryptographically broken. Exhaustive key-search attacks are feasible on commodity hardware. Replace with AES-256-GCM immediately..'
      },
      {
        name:'user-passwords-v1', purpose:'MD5 (unsalted) | Password hash store',
        algorithm:'MD5', keySize:'128-bit output', useCase:'Password storage (unsalted)', lastUpdated:'2011',
        ragAnswer:'R', actionAnswer:'replace',
        notes:'MD5 is a fast hash with known collision vulnerabilities. Used unsalted for passwords, it is trivially defeated by rainbow table attacks. Replace with bcrypt (work factor ≥12) or Argon2id immediately..'
      },
      {
        name:'legacy-vpn-stream', purpose:'RC4 | VPN session encryption',
        algorithm:'RC4', keySize:'128 bits', useCase:'VPN traffic encryption (in transit)', lastUpdated:'2013',
        ragAnswer:'R', actionAnswer:'replace',
        notes:'RC4 stream cipher has been prohibited by IETF (RFC 7465) since 2015 due to statistical biases in its keystream. Forbidden in TLS. Replace with AES-256-GCM or ChaCha20-Poly1305..'
      },
      {
        name:'api-key-exchange', purpose:'RSA-512 | API key exchange',
        algorithm:'RSA', keySize:'512 bits', useCase:'Asymmetric key exchange', lastUpdated:'2007',
        ragAnswer:'R', actionAnswer:'replace',
        notes:'RSA-512 can be factored in hours on standard hardware. NIST minimum is RSA-2048. This key exchange provides no meaningful security — replace with RSA-2048 or ECDH immediately..'
      },
      // AMBER — weakening, schedule replacement
      {
        name:'cert-signing-internal', purpose:'SHA-1 | Internal certificate signing',
        algorithm:'SHA-1', keySize:'160-bit output', useCase:'Digital signatures (certificates)', lastUpdated:'2016',
        ragAnswer:'A', actionAnswer:'schedule',
        notes:'SHA-1 was deprecated by NIST in 2011 and browsers began refusing SHA-1 certificates from 2017. Collision attacks are now practical (SHAttered, 2017). Not immediately broken but schedule migration to SHA-256..'
      },
      {
        name:'backup-encrypt-legacy', purpose:'3DES-112 | Backup file encryption',
        algorithm:'3DES (Triple-DES)', keySize:'112 bits effective', useCase:'Data at rest (backups)', lastUpdated:'2014',
        ragAnswer:'A', actionAnswer:'schedule',
        notes:'3DES has an effective key length of 112 bits due to the meet-in-the-middle attack. NIST deprecated it in 2017 and disallows it from 2024. Still offers some security but schedule migration to AES-256..'
      },
      {
        name:'file-store-aes128', purpose:'AES-128-CBC | Document store encryption',
        algorithm:'AES-128-CBC', keySize:'128 bits', useCase:'Data at rest (document storage)', lastUpdated:'2019',
        ragAnswer:'A', actionAnswer:'schedule',
        notes:'AES-128 is technically sound but CBC mode has padding oracle vulnerabilities. NIST now recommends AES-256-GCM (authenticated encryption). Not urgent but schedule upgrade during next maintenance window..'
      },
      {
        name:'rsa-1024-signing', purpose:'RSA-1024 | Legacy document signing',
        algorithm:'RSA', keySize:'1024 bits', useCase:'Digital signatures (documents)', lastUpdated:'2015',
        ragAnswer:'A', actionAnswer:'schedule',
        notes:'RSA-1024 is below NIST\'s recommended minimum of 2048 bits. While not immediately vulnerable, factoring attacks are advancing. Schedule migration to RSA-2048 or ECDSA-256..'
      },
      // GREEN — current best practice, maintain
      {
        name:'db-encrypt-primary', purpose:'AES-256-GCM | Primary database encryption',
        algorithm:'AES-256-GCM', keySize:'256 bits', useCase:'Data at rest (primary database)', lastUpdated:'2022',
        ragAnswer:'G', actionAnswer:'maintain',
        notes:'AES-256-GCM is the current gold standard for symmetric encryption. GCM mode provides both confidentiality and integrity (authenticated encryption). No action required..'
      },
      {
        name:'tls-key-exchange', purpose:'RSA-2048 | TLS key exchange',
        algorithm:'RSA', keySize:'2048 bits', useCase:'Asymmetric key exchange (TLS)', lastUpdated:'2021',
        ragAnswer:'G', actionAnswer:'maintain',
        notes:'RSA-2048 meets NIST\'s current minimum recommendation. Appropriate for TLS key exchange. Review in 2030 when RSA-3072 will be recommended. No immediate action required..'
      },
      {
        name:'user-passwords-v2', purpose:'bcrypt (work factor 12) | Password store',
        algorithm:'bcrypt', keySize:'192-bit output + salt', useCase:'Password storage', lastUpdated:'2022',
        ragAnswer:'G', actionAnswer:'maintain',
        notes:'bcrypt is a password-hashing function designed to be computationally slow and salted. Work factor 12 is appropriate for current hardware. Correct tool for password storage — not a general-purpose hash..'
      },
      {
        name:'file-integrity-check', purpose:'SHA-256 | File integrity verification',
        algorithm:'SHA-256', keySize:'256-bit output', useCase:'Integrity verification (checksums)', lastUpdated:'2023',
        ragAnswer:'G', actionAnswer:'maintain',
        notes:'SHA-256 is the current standard for integrity verification. Part of the SHA-2 family, it has no known practical attacks. Correct use case — verifying file integrity, not password storage. No action required..'
      },
    ];
    const nR=pick([1,2,2]);
    const nA=pick([1,1,2]);
    const nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Cryptography & Key Management Team', incorrect:'Facilities Management' },
  reportHint: 'Cryptographic vulnerabilities require specialist remediation — which team manages keys and cipher selection?',

  completionText(_,sc){
    const crit=sc.filter(s=>s.ragAnswer==='R').length;
    return `<div class="rc info"><h3>ENCRYPTION AUDIT — KEY PRINCIPLES</h3>
    <p>${crit} critical finding(s) identified. Key distinctions: <strong>symmetric</strong> (AES — one shared key, fast, bulk data) vs <strong>asymmetric</strong> (RSA — public/private pair, slow, key exchange) vs <strong>hashing</strong> (SHA-256, bcrypt — one-way, integrity/passwords).</p>
    <p style="margin-top:8px;"><strong>Key concepts:</strong> Symmetric encryption (AES — one shared key), asymmetric encryption (RSA — public/private pair), hashing (one-way: SHA-256 for integrity, bcrypt for passwords). Each has distinct use cases.</p></div>`;
  },

  actions:{ R:'replace', A:'schedule', G:'maintain' },
  actionLabels:{ replace:'🔴 REPLACE URGENTLY', schedule:'🟡 SCHEDULE REPLACEMENT', maintain:'✅ MAINTAIN' },
  ragRules:{
    R:'Cryptographically broken: DES, MD5/SHA-1 for passwords, RC4, RSA<1024 → REPLACE URGENTLY',
    A:'Weakening: SHA-1 for certs, 3DES, AES-128-CBC, RSA-1024 → SCHEDULE REPLACEMENT',
    G:'Current best practice: AES-256-GCM, RSA-2048+, bcrypt, SHA-256 → MAINTAIN',
  },

  plenary:{
    reportHint: 'Cryptographic vulnerabilities require specialist remediation — which team manages keys and cipher selection?',
    analogy: 'Auditing encryption configurations is like inspecting a building\'s locks: some are strong deadbolts (AES-256), some are old padlocks that were once fine but are now pickable (3DES, SHA-1), and some were never secure to begin with (DES-56, MD5 for passwords). Each needs a different response.',
    whatHappened: 'The audit revealed a mix of critically broken algorithms (DES, MD5, RC4) still in active use, legacy systems that need scheduled migration (3DES, SHA-1, RSA-1024), and correctly configured modern cryptography. The critical findings represent immediate risk to data confidentiality.',
    keyMove: 'Symmetric encryption uses one shared key (AES = current standard; DES = broken). Asymmetric uses public/private pairs (RSA-2048 = minimum; RSA-512 = replace now). Hashing is one-way — use SHA-256 for integrity, bcrypt/Argon2 for passwords (NOT MD5 or SHA-1).',
    realWorld: 'LinkedIn\'s 2012 breach demonstrated exactly what happens when fast, unsalted hashes protect passwords: 117 million accounts were compromised because SHA-1 without salt can be attacked with rainbow tables. The distinction between encryption (reversible) and hashing (one-way) — and choosing the right algorithm for the job — is precisely why password stores still get breached.',
    quiz:[
      {q:'Which of the following correctly describes symmetric encryption?',options:['Uses a public key to encrypt and a separate private key to decrypt','Uses the same key for both encryption and decryption','Produces a fixed-length output from which the original data cannot be derived'],correct:1},
      {q:'To send a confidential message to Alice using asymmetric encryption, you would encrypt it with:',options:['Your own private key — proving you sent it','Alice\'s private key — giving her exclusive access','Alice\'s public key — only her private key can then decrypt it'],correct:2},
      {q:'Which of the following is a hashing algorithm rather than an encryption algorithm?',options:['AES-256 (used for encrypting files)','RSA-2048 (used for key exchange)','SHA-256 (used for integrity checking)'],correct:2},
      {q:'A hash function is described as "one-way". This means:',options:['It can only be applied once per document — not reversible by further hashing','The original data cannot be mathematically derived from the hash value alone','It only works in one direction: from server to client'],correct:1},
      {q:'MD5 is no longer considered safe for password storage primarily because:',options:['It produces digests that are too short to be unique across all possible inputs','It is a symmetric cipher and requires secure key distribution between parties','It is vulnerable to rainbow table attacks and collisions can be found practically'],correct:2},
      {q:'A digital signature is created using:',options:['The sender\'s private key — allowing anyone with the public key to verify authenticity','The recipient\'s public key — ensuring only the recipient can read the message','A shared symmetric key — agreed in advance using Diffie-Hellman exchange'],correct:0},
      {q:'AES-256 used to encrypt a backup file is an example of:',options:['Asymmetric encryption — using a public/private key pair','Hashing — producing a one-way digest of the file contents','Symmetric encryption — using a single shared key for both encryption and decryption'],correct:2},
      {q:'Why is asymmetric encryption typically used for key exchange rather than bulk data encryption?',options:['It cannot process data larger than the key size in bits','The mathematical operations (e.g. modular exponentiation of large primes) are significantly slower than symmetric ciphers','Both parties must be online simultaneously for asymmetric encryption to function'],correct:1},
      {q:'A "salt" added to a password before hashing prevents:',options:['The hash from being stored in plaintext in the database','Two identical passwords producing identical hash values — defeating precomputed rainbow table attacks','The password from being transmitted over the network in plaintext'],correct:1},
    ]
  }
};


// ═══════════════════════════════════════════════════════════
// MODULE 3: SQL INJECTION DETECTION
// H446 §1.3.2 — Databases, SQL, normalisation, transactions
// ═══════════════════════════════════════════════════════════
MODULES.sqlInjection = {
  id: 'sqlInjection',
  name: 'SQL INJECTION DETECTION',

  emailSender: ()=>pick(['waf@secops.internal','appsec@infrasec.net','dba@database-ops.io','appsec-alerts@company.net']),
  emailSubject: ()=>pick(['WAF Alert: Potential SQL Injection Attempts Detected','Application Security Alert: Suspicious Database Queries','DBA Notice: Anomalous Input Detected in Application Logs','AppSec P2 Alert: SQL Metacharacters in Form Submissions']),
  emailBody(){
    return pick([
      `Analyst,\n\nOur Web Application Firewall has flagged a number of submissions to application endpoints over the last hour. Some contain SQL metacharacters that could indicate injection attempts; others may be legitimate.\n\nLoad the SQL Query Log Viewer. Carefully review the submitted value for each entry — look for SQL keywords, quote characters, comment sequences and tautologies.\n\nApplication Security Team`,
      `Hi,\n\nThe DBA team have noticed some unusual activity in the application query logs. At least one submission appears to be attempting database enumeration.\n\nUse the SQL Query Log Viewer to triage each logged submission. Consider the endpoint, the input field, and whether the submitted value could modify the intended query structure.\n\nDatabase Operations`,
      `Analyst,\n\nFollowing last month's breach at a competitor via SQL injection, we're reviewing our own application input logs proactively. Some of these look suspicious; others are false positives from legitimate user input.\n\nReview the WAF log using the SQL Query Log Viewer. Your job is to distinguish genuine attack attempts from legitimate submissions.\n\nAppSec`
    ]);
  },

  tools: {
    correct: 'SQL Query Log Viewer',
    decoys: ['Packet Capture Analyser','Encryption Audit Tool','Firewall Rule Manager','Legal Reference Database','Network Traffic Monitor','Process Monitor','Email Header Analyser']
  },

  briefing: {
    title: 'SQL Injection Detection',
    tagline: 'Identifying malicious database queries in application input logs',
    summary: "SQL injection occurs when unsanitised user input is incorporated directly into a database query. If an attacker enters ' OR '1'='1 -- into a login form, the resulting SQL makes the WHERE clause always true — bypassing authentication entirely. The double-hyphen (--) begins a SQL comment, causing the rest of the query to be ignored. More destructive payloads use UNION SELECT to exfiltrate data, or DROP TABLE to destroy it. The defence: parameterised queries (prepared statements) separate SQL code from user data, making injection structurally impossible.",
    watchFor: "Single quotes (') in unexpected contexts • OR/AND with always-true conditions (1=1, 'a'='a') • Comment sequences: -- or /* */ • UNION SELECT (data exfiltration) • Semicolons followed by SQL keywords (query chaining) • EXEC or xp_cmdshell (OS command execution via SQL Server) • HTTP 500 errors from an endpoint after unusual input",
    realWorld: "In 2008 Heartland Payment Systems suffered one of the largest card breaches in history: 130 million credit card numbers stolen via SQL injection against a vulnerable web form. A single unparameterised query allowed attackers to install a packet sniffer on the payment network. Heartland paid over $140 million in settlements. The fix — parameterised queries — would have cost virtually nothing to implement."
  },

  generateScenario({numItems=6}={}){
    const pool = [
      // RED — clear SQL injection attacks
      {
        name:'/api/v1/auth/login', purpose:'POST — user authentication endpoint',
        endpoint:'/api/v1/auth/login', inputField:'username', submittedValue:"' OR '1'='1' --",
        responseCode:'200 OK', rate:'1 req',
        ragAnswer:'R', actionAnswer:'block',
        notes:"Classic authentication bypass: the injected payload makes the WHERE clause evaluate to TRUE for every row, returning the first user (often admin). The -- comment discards the rest of the query. This is a textbook SQL injection. Block and alert the DBA."
      },
      {
        name:'/search', purpose:'GET — product search endpoint',
        endpoint:'/search', inputField:'q', submittedValue:"1; DROP TABLE orders; --",
        responseCode:'500 Internal Server Error', rate:'1 req',
        ragAnswer:'R', actionAnswer:'block',
        notes:"Destructive query chaining: a semicolon terminates the SELECT and begins a new DROP TABLE statement — permanently deleting the orders table and all its data. The 500 error may indicate the payload partially executed. Block and escalate to DBA immediately."
      },
      {
        name:'/api/v2/products', purpose:'GET — product listing with ID filter',
        endpoint:'/api/v2/products', inputField:'id', submittedValue:"1 UNION SELECT username, password_hash, email FROM users --",
        responseCode:'200 OK', rate:'3 reqs',
        ragAnswer:'R', actionAnswer:'block',
        notes:"UNION-based data exfiltration: the UNION SELECT appends a second query, returning rows from the users table alongside the product results. The attacker is enumerating password hashes and emails. Block source IP and rotate database credentials immediately."
      },
      {
        name:'/admin/exec', purpose:'POST — admin query execution endpoint',
        endpoint:'/admin/exec', inputField:'query', submittedValue:"'; EXEC xp_cmdshell('whoami'); --",
        responseCode:'200 OK', rate:'1 req',
        ragAnswer:'R', actionAnswer:'block',
        notes:"OS command injection via SQL Server's xp_cmdshell stored procedure. If enabled, this executes an operating system command as the SQL Server service account. This is a critical P1 incident — block, isolate the DB server and escalate to CISO."
      },
      {
        name:'/api/v1/user/profile', purpose:'GET — user profile lookup by ID',
        endpoint:'/api/v1/user/profile', inputField:'user_id', submittedValue:"admin' --",
        responseCode:'200 OK', rate:'1 req',
        ragAnswer:'R', actionAnswer:'block',
        notes:"Authentication bypass using comment injection: appending -- after 'admin' comments out any password check in the query (e.g. WHERE username='admin'--' AND password=...). If the application returned a valid profile, the database is vulnerable."
      },
      // AMBER — suspicious, requires review
      {
        name:'/forms/contact', purpose:'POST — contact form submission',
        endpoint:'/forms/contact', inputField:'name', submittedValue:"Robert'); DROP TABLE students; --",
        responseCode:'400 Bad Request', rate:'1 req',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:"This is the famous 'Little Bobby Tables' payload (XKCD 327). The 400 response suggests the WAF or input validation caught it — but it indicates someone tested an injection vector. Investigate source IP for further probing activity."
      },
      {
        name:'/api/v3/search', purpose:'GET — customer search endpoint',
        endpoint:'/api/v3/search', inputField:'query', submittedValue:"dXNlcm5hbWUgT1IgMT0x (base64)",
        responseCode:'200 OK', rate:'12 reqs',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:"Base64-encoded payload: decodes to 'username OR 1=1'. Multiple requests (12) suggest automated scanning. The attacker is testing whether the application decodes user input before passing it to the database — an obfuscation attempt. Investigate and review WAF decode rules."
      },
      {
        name:'/api/v1/register', purpose:'POST — new account registration',
        endpoint:'/api/v1/register', inputField:'email', submittedValue:"test@test.com' AND '1",
        responseCode:'422 Unprocessable Entity', rate:'1 req',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:"Potential blind SQL injection probe: the trailing ' AND '1 is testing whether the application processes the quote without sanitisation. The 422 response suggests validation exists, but the input pattern warrants investigation to confirm the endpoint is parameterised."
      },
      // GREEN — legitimate form submissions
      {
        name:'/api/v1/auth/login', purpose:'POST — user authentication endpoint',
        endpoint:'/api/v1/auth/login', inputField:'username', submittedValue:"alice.smith@company.com",
        responseCode:'200 OK', rate:'1 req',
        ragAnswer:'G', actionAnswer:'allow',
        notes:"Normal login submission. Email address format, no SQL metacharacters, rate of one request. No indicators of injection. Allow."
      },
      {
        name:'/search', purpose:'GET — product search endpoint',
        endpoint:'/search', inputField:'q', submittedValue:"blue wireless headphones",
        responseCode:'200 OK', rate:'4 reqs',
        ragAnswer:'G', actionAnswer:'allow',
        notes:"Normal search query. Natural language text, no SQL keywords or metacharacters. Four requests in the session is consistent with a user refining their search. Allow."
      },
      {
        name:'/forms/contact', purpose:'POST — contact form submission',
        endpoint:'/forms/contact', inputField:'name', submittedValue:"O'Brien",
        responseCode:'200 OK', rate:'1 req',
        ragAnswer:'G', actionAnswer:'allow',
        notes:"Edge case: O'Brien contains a single quote — a legitimate Irish surname. The application's parameterised query handles this correctly. A single apostrophe in a name field is not an injection attempt without additional SQL syntax. Allow."
      },
      {
        name:'/api/v2/products', purpose:'GET — product listing with ID filter',
        endpoint:'/api/v2/products', inputField:'id', submittedValue:"4821",
        responseCode:'200 OK', rate:'2 reqs',
        ragAnswer:'G', actionAnswer:'allow',
        notes:"Normal integer product ID. No SQL metacharacters, rate is consistent with a user viewing product pages. Allow."
      },
    ];
    const nR=pick([1,2,2,3]);
    const nA=pick([0,1,1,2]);
    const nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Application Security & DBA Team', incorrect:'Marketing Department' },
  reportHint: 'SQL injection targets the database layer — which team owns application security and database administration?',

  completionText(_,sc){
    const att=sc.filter(s=>s.ragAnswer!=='G').length;
    return `<div class="rc info"><h3>SQL INJECTION — KEY PRINCIPLES</h3>
    <p>${att} suspicious submission(s) identified. The fix is always <strong>parameterised queries</strong> (prepared statements): SQL code and user data are sent separately, making injection structurally impossible regardless of what characters the user submits.</p>
    <p style="margin-top:8px;"><strong>Key concepts:</strong> SQL syntax (SELECT, DROP, UNION), injection attack vectors, parameterised queries as the fix, relational database concepts (primary/foreign keys, normalisation, ACID transactions).</p></div>`;
  },

  actions:{ R:'block', A:'investigate', G:'allow' },
  actionLabels:{ block:'🚫 BLOCK & ALERT DBA', investigate:'🔍 FLAG FOR REVIEW', allow:'✅ ALLOW (LEGITIMATE)' },
  ragRules:{
    R:'Clear injection payload: SQL metacharacters with attack syntax → BLOCK & ALERT DBA',
    A:'Suspicious input: encoded payload, partial syntax, probe pattern → FLAG & INVESTIGATE',
    G:'Legitimate input: no SQL syntax, expected field content → ALLOW',
  },

  plenary:{
    reportHint: 'SQL injection targets the database layer — which team owns application security and database administration?',
    analogy: 'SQL injection is like a form asking for your name, and someone writing "Alice OR everyone is Alice". The form was designed for a single name, but the "OR everyone is Alice" logic gets passed to the database which then returns every record — the attacker provided code disguised as data.',
    whatHappened: 'Several endpoints were being probed with SQL injection payloads ranging from classic authentication bypasses to destructive DROP TABLE commands and data-exfiltration UNION SELECT attacks. One legitimate submission containing an apostrophe (O\'Brien) required careful distinction from attack payloads.',
    keyMove: "Single quote + SQL keyword (OR, UNION, DROP, EXEC) + comment (--, /*) = injection attempt (RED). Base64/encoded payloads or trailing quote with no SQL keyword = suspicious probe (AMBER). Natural text, email addresses, integers with no SQL metacharacters = legitimate (GREEN).",
    realWorld: 'The Heartland Payment Systems breach (2008) — 130 million card numbers stolen — began with a single SQL injection in a web form. The entire incident could have been prevented by parameterised queries — one of the simplest, most important security practices in database-backed application development.',
    quiz:[
      {q:"SQL injection exploits the fact that user-supplied input is incorporated directly into a query. Why is this fundamentally dangerous?",options:['It allows the input to exceed the maximum field length, crashing the database','User input can change the STRUCTURE of the SQL query, not just supply data values','It prevents the database from caching queries efficiently'],correct:1},
      {q:"A login query reads: SELECT * FROM users WHERE username='[input]' AND password='[input]'. An attacker submits the username: ' OR '1'='1' -- \nWhat does the resulting WHERE clause evaluate to, and why does the login succeed?",options:['The clause becomes invalid SQL and the database skips authentication entirely','The clause always evaluates to TRUE for every row — the OR condition short-circuits the password check, and -- comments out the rest','The clause creates a new admin user with a blank password'],correct:1},
      {q:"The payload admin'-- is submitted as a username. The -- sequence causes:",options:['The database to execute the query twice, returning duplicate rows','Everything after it to be treated as a comment — the password check is discarded, and the query returns the admin row','The query to be logged but not executed, bypassing auditing'],correct:1},
      {q:'Parameterised queries (prepared statements) prevent SQL injection because:',options:['They automatically escape all special characters before they reach the database','SQL code and user data are sent to the database separately — user input is never interpreted as SQL syntax','They limit the length of user input to prevent buffer overflow attacks'],correct:1},
      {q:"A UNION SELECT injection — e.g. 1 UNION SELECT username, password FROM users -- works by:",options:['Replacing the original query entirely with the attacker\'s query','Appending a second SELECT query whose results are returned alongside the original — exposing data from a second table','Locking the target table so legitimate users cannot access it'],correct:1},
      {q:"The payload '; EXEC xp_cmdshell('whoami'); -- is particularly dangerous because:",options:['It changes the database owner password to a known value','xp_cmdshell is a SQL Server stored procedure that executes operating system commands — this escalates from database access to OS-level control','It exports the entire database to a publicly accessible file path'],correct:1},
      {q:'A web endpoint returns HTTP 500 Internal Server Error immediately after a form submission containing a single apostrophe. A security analyst should consider this:',options:['Normal — apostrophes in names like O\'Brien commonly cause formatting issues','A strong indicator of SQL injection vulnerability — the apostrophe broke the query syntax and the database returned an unhandled error','An indication that the server is under DDoS attack'],correct:1},
      {q:"Which of the following inputs is the most dangerous to pass to a login form that concatenates user input directly into a SQL query?",options:["A very long string of repeating characters (aaaaaaaaaa...)","The value: ' OR 1=1; DROP TABLE users; --","A valid email address containing a + character"],correct:1},
      {q:'The only fully reliable defence against SQL injection is:',options:['Filtering and blocking all inputs containing single quotes or SQL keywords','Using parameterised queries — structurally separating SQL code from user data so that input cannot alter query logic regardless of content','Hashing all user input before it reaches the database layer'],correct:1},
    ]
  }
};


// ═══════════════════════════════════════════════════════════
// MODULE 4: FIREWALL RULE CHANGE REVIEW
// H446 §1.3.3 — Firewalls, proxies, network security
// ═══════════════════════════════════════════════════════════
MODULES.firewallReview = {
  id: 'firewallReview',
  name: 'FIREWALL RULE CHANGE REVIEW',

  emailSender: ()=>pick(['change-mgmt@infrasec.net','network-ops@company.net','noc@security.internal','it-change@company.net']),
  emailSubject: ()=>pick(['Change Requests: Firewall Rule Amendments — Analyst Approval Required','Network Change Management: Firewall Rules Awaiting Triage','IT Change Board: Firewall Rule Review Pending','NOC: Proposed Firewall Changes — Security Sign-Off Needed']),
  emailBody(){
    return pick([
      `Analyst,\n\nSeveral firewall rule change requests have been submitted this week. Some are routine and straightforward; others require careful scrutiny before approval.\n\nLoad the Firewall Rule Manager. For each request, assess whether the proposed change is safe to approve, needs escalation for further review, or should be rejected as a security risk.\n\nApply the principle of least privilege: access should be granted only where there is a clear, justified business need.\n\nNetwork Operations`,
      `Hi,\n\nChange Management have queued a batch of firewall rule requests. I need a second set of eyes on these before they go to the Change Board.\n\nSome look fine; a couple I'm concerned about. Use the Firewall Rule Manager to assess each one. Key questions: is this port/protocol combination safe? Is the justification specific and plausible? Could this be more tightly scoped?\n\nSecurity Architecture`,
      `Analyst,\n\nFollowing last quarter's red team exercise — which used an overly-permissive outbound rule as a C2 channel — we're applying closer scrutiny to all firewall change requests.\n\nReview the queued changes using the Firewall Rule Manager. Reject anything that unnecessarily expands the attack surface. Escalate anything ambiguous.\n\nCISO Office`
    ]);
  },

  tools: {
    correct: 'Firewall Rule Manager',
    decoys: ['Packet Capture Analyser','Encryption Audit Tool','SQL Query Log Viewer','Legal Reference Database','Process Monitor','Email Header Analyser','Certificate Checker']
  },

  briefing: {
    title: 'Firewall Rule Change Review',
    tagline: 'Evaluating network access control requests against security principles',
    summary: 'A firewall controls which traffic is permitted to enter and leave a network by matching packets against an ordered ruleset. Stateful firewalls additionally track connection state, allowing returning traffic for established sessions. Proxy servers add a layer between client and server, filtering content and masking internal IP addresses. The principle of least privilege mandates granting only the minimum access required. A single misconfigured rule — opening SSH or RDP to the internet, or allowing unrestricted outbound access — can compromise an entire network.',
    watchFor: 'Rules allowing inbound traffic from 0.0.0.0/0 (any IP — the entire internet) on sensitive ports • High-risk ports open to internet: 22 (SSH), 23 (Telnet), 3389 (RDP), 5900 (VNC) • Overly broad port ranges (0–65535 all ports) • Outbound rules to any destination with no destination restriction • Rules with vague justification ("business need", "developer request") • Any use of Telnet (unencrypted) instead of SSH',
    realWorld: 'The 2020 SolarWinds supply chain attack exploited a legitimate firewall rule permitting the Orion monitoring software to make outbound HTTP connections to the internet. Attackers embedded a backdoor in a software update and used this rule as a covert C2 channel — the rule was never questioned because it appeared routine. Over 18,000 organisations were compromised before the attack was detected months later.'
  },

  generateScenario({numItems=6}={}){
    const pool = [
      // RED — reject immediately
      {
        name:'CR-2025-0041', purpose:'Allow ALL inbound TCP port 22 (SSH) from internet',
        protocol:'TCP', port:'22', direction:'Inbound', requestedBy:'Dev Team', justification:'Remote server management',
        ragAnswer:'R', actionAnswer:'reject',
        notes:'Exposing SSH (port 22) to 0.0.0.0/0 (the entire internet) creates an enormous attack surface for brute-force and credential stuffing attacks. Reject. Proper practice: restrict SSH access to specific known admin IP ranges, or require VPN access first.'
      },
      {
        name:'CR-2025-0044', purpose:'Allow inbound TCP port 3389 (RDP) from 0.0.0.0/0',
        protocol:'TCP', port:'3389', direction:'Inbound', requestedBy:'IT Support', justification:'Remote desktop access for support',
        ragAnswer:'R', actionAnswer:'reject',
        notes:'RDP exposed to the internet is one of the most commonly exploited configurations — used in ransomware attacks including WannaCry and NotPetya. Reject. Require VPN + MFA before any internal RDP is accessible, never expose port 3389 directly.'
      },
      {
        name:'CR-2025-0047', purpose:'Allow outbound TCP port 23 (Telnet) to any destination',
        protocol:'TCP', port:'23', direction:'Outbound', requestedBy:'Legacy Systems Team', justification:'Connection to legacy router management',
        ragAnswer:'R', actionAnswer:'reject',
        notes:'Telnet transmits all data — including credentials — in plaintext. It was superseded by SSH in 1995. Reject and require migration to SSH for all remote management. This is not a timing issue; Telnet should never be used.'
      },
      {
        name:'CR-2025-0053', purpose:'Allow outbound TCP 0–65535 (all ports) from Finance workstations',
        protocol:'TCP', port:'0–65535', direction:'Outbound', requestedBy:'Finance Manager', justification:'Application accessing various cloud services',
        ragAnswer:'R', actionAnswer:'reject',
        notes:'Permitting all outbound ports from Finance workstations would allow malware on those machines to contact any C2 server on any port — and would permit data exfiltration on non-standard ports. Reject. Request a specific list of destination services and open only those ports.'
      },
      // AMBER — escalate for further review
      {
        name:'CR-2025-0038', purpose:'Allow inbound HTTPS (443) from subnet 192.168.50.0/24 to app server',
        protocol:'TCP', port:'443', direction:'Inbound', requestedBy:'App Team', justification:'Internal app team testing new microservice',
        ragAnswer:'A', actionAnswer:'escalate',
        notes:'HTTPS on port 443 to a specific internal subnet is lower risk than internet-facing, but the justification lacks specifics: which app server? What microservice? When does this expire? Escalate to confirm the source subnet, destination, and add an expiry date. Not automatically safe without these details.'
      },
      {
        name:'CR-2025-0049', purpose:'Allow outbound TCP 8080 from developer workstations to any',
        protocol:'TCP', port:'8080', direction:'Outbound', requestedBy:'Development Lead', justification:'Developer tools and API testing',
        ragAnswer:'A', actionAnswer:'escalate',
        notes:'Port 8080 is a common alternative HTTP port used by development tools. The destination ("any") is too broad — this could be scoped to specific development environments. Escalate to determine if destination can be restricted. Not an immediate reject, but needs tightening.'
      },
      {
        name:'CR-2025-0055', purpose:'Allow inbound TCP 5900 (VNC) from 10.20.0.0/16 to server farm',
        protocol:'TCP', port:'5900', direction:'Inbound', requestedBy:'Systems Administrator', justification:'Remote server console access from management VLAN',
        ragAnswer:'A', actionAnswer:'escalate',
        notes:'VNC on port 5900 from a /16 internal subnet (/16 = 65,536 addresses). The management VLAN access is plausible, but the scope is too wide. Escalate: can this be restricted to specific admin host IPs? VNC access to servers should require strong authentication.'
      },
      // GREEN — approve
      {
        name:'CR-2025-0033', purpose:'Allow inbound HTTPS (443) to web server in DMZ from internet',
        protocol:'TCP', port:'443', direction:'Inbound', requestedBy:'Web Team', justification:'Public-facing web application requires HTTPS access',
        ragAnswer:'G', actionAnswer:'approve',
        notes:'Standard configuration for a public web server in the DMZ. HTTPS on port 443 is the expected protocol. Web servers in the DMZ are designed to accept inbound internet connections — this is the intended network architecture. Approve.'
      },
      {
        name:'CR-2025-0036', purpose:'Allow outbound HTTPS (443) from internal hosts to Microsoft Update servers',
        protocol:'TCP', port:'443', direction:'Outbound', requestedBy:'IT Infrastructure', justification:'Windows Update and Microsoft 365 traffic',
        ragAnswer:'G', actionAnswer:'approve',
        notes:'Outbound HTTPS to Microsoft Update CDN addresses is standard and required for patch management. Well-documented, specific destination, legitimate business justification. Approve.'
      },
      {
        name:'CR-2025-0039', purpose:'Allow outbound UDP 53 (DNS) to company DNS servers only',
        protocol:'UDP', port:'53', direction:'Outbound', requestedBy:'Network Team', justification:'DNS queries from internal hosts to managed resolvers',
        ragAnswer:'G', actionAnswer:'approve',
        notes:'Restricting DNS queries to company-managed resolvers (rather than allowing DNS to any external server) is a security best practice — it prevents DNS tunnelling to arbitrary external servers. Tightly scoped and justified. Approve.'
      },
      {
        name:'CR-2025-0042', purpose:'Allow inbound SMTP (25) to mail relay in DMZ from internet',
        protocol:'TCP', port:'25', direction:'Inbound', requestedBy:'Email Infrastructure', justification:'Inbound email delivery from external mail servers',
        ragAnswer:'G', actionAnswer:'approve',
        notes:'A mail relay in the DMZ accepting inbound SMTP on port 25 from the internet is standard email infrastructure. The relay should be isolated in the DMZ and forward only to the internal mail server. This is expected and correctly scoped. Approve.'
      },
    ];
    const nR=pick([1,2,2]);
    const nA=pick([1,1,2]);
    const nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Security Architecture Team', incorrect:'Human Resources Department' },
  reportHint: 'Firewall misconfiguration is a network architecture risk — which team owns security design decisions?',

  completionText(_,sc){
    const rej=sc.filter(s=>s.ragAnswer==='R').length;
    return `<div class="rc info"><h3>FIREWALL REVIEW — KEY PRINCIPLES</h3>
    <p>${rej} rule(s) rejected. Core principle: <strong>principle of least privilege</strong> — grant only the minimum access required. Every rule that opens a port increases the attack surface. Reject before Escalate before Approve.</p>
    <p style="margin-top:8px;"><strong>Key concepts:</strong> Principle of least privilege, stateful vs stateless firewalls, DMZ architecture, high-risk ports (22/SSH, 3389/RDP, 23/Telnet), 0.0.0.0/0 meaning any internet address.</p></div>`;
  },

  actions:{ R:'reject', A:'escalate', G:'approve' },
  actionLabels:{ reject:'🚫 REJECT', escalate:'🟡 ESCALATE FOR REVIEW', approve:'✅ APPROVE' },
  ragRules:{
    R:'Security risk: exposes sensitive ports or services to untrusted networks → REJECT',
    A:'Requires further information: too broad, insufficient justification → ESCALATE',
    G:'Appropriate, justified, tightly scoped access control change → APPROVE',
  },

  plenary:{
    reportHint: 'Firewall misconfiguration is a network architecture risk — which team owns security design decisions?',
    analogy: 'Reviewing firewall rules is like approving keys to a building. Most requests are reasonable (front door key for the receptionist). Some need more thought (why does the cleaner need a key to the server room?). And some should be refused outright (why does an intern need a master key to every door?).',
    whatHappened: 'A batch of change requests ranged from clear rejections (SSH and RDP exposed to the internet, Telnet, all-ports outbound) to requests needing tighter scoping (broad subnets, missing expiry dates) to entirely legitimate and appropriate rules (HTTPS to DMZ web server, DNS to managed resolvers).',
    keyMove: '0.0.0.0/0 = any IP on the internet. Port 22 (SSH), 3389 (RDP), 23 (Telnet), 5900 (VNC) to internet = reject. All-ports outbound = reject. HTTPS to DMZ web server = standard, approve. Always ask: can this be more tightly scoped? Is the justification specific?',
    realWorld: 'The SolarWinds attack (2020) used a legitimate, unquestioned outbound firewall rule as a covert C2 channel. 18,000 organisations were compromised. The rule appeared routine — it was not. Understanding exactly what a firewall rule permits — and what it silently allows — is what separates a security-aware network engineer from one who just ticks boxes.',
    quiz:[
      {q:'Port 22 is used by which secure remote access protocol?',options:['RDP — Remote Desktop Protocol, providing a graphical desktop interface','SSH — Secure Shell, providing encrypted command-line access','FTP — File Transfer Protocol, for transferring files between systems'],correct:1},
      {q:'Why is Telnet (port 23) considered insecure for remote server management?',options:['It uses an outdated authentication mechanism that limits passwords to 8 characters','It transmits all data, including credentials, in plaintext over the network','It is too slow for modern high-bandwidth networks'],correct:1},
      {q:'0.0.0.0/0 in a firewall rule refers to:',options:['The loopback address, meaning only local connections are permitted','Any IP address — effectively the entire internet, with no source restriction','The default gateway — the router connecting the internal network to the internet'],correct:1},
      {q:'A DMZ (Demilitarised Zone) in network architecture is:',options:['A wireless network segment reserved for guest devices only','A subnetwork positioned between the private internal network and the untrusted internet, hosting internet-facing services','A virtual private network tunnel for remote employees'],correct:1},
      {q:'The principle of least privilege states that:',options:['All users should be granted administrator rights by default, revoked only if misused','Users and systems should be granted only the minimum access rights necessary to perform their function','Privileged administrators should use the least secure authentication method to simplify access'],correct:1},
      {q:'RDP (Remote Desktop Protocol) uses which default port?',options:['443 — the standard HTTPS port, making it appear as web traffic','22 — the same as SSH, as both provide remote access','3389 — a dedicated port; exposing it to the internet is a common attack vector'],correct:2},
      {q:'A forward proxy in a corporate network:',options:['Accepts inbound internet connections on behalf of a web server, masking the server\'s internal IP','Makes outbound requests on behalf of internal clients, masking their internal IP addresses from external servers','Replaces the function of the internal DNS server for hostname resolution'],correct:1},
      {q:'A stateful firewall differs from a stateless packet filter in that it:',options:['Only examines the source/destination IP and port number of each packet in isolation','Tracks the state of connections and automatically allows return traffic for established sessions','Blocks all inbound traffic by default and must be explicitly told to permit every packet'],correct:1},
      {q:'A next-generation firewall (NGFW) provides capabilities beyond a traditional firewall, including:',options:['Physical network switch functionality and VLAN management','Deep packet inspection, application-layer awareness and integrated intrusion detection/prevention','Wireless access point management and spectrum analysis'],correct:1},
    ]
  }
};


// ═══════════════════════════════════════════════════════════
// MODULE 5: LEGAL & COMPLIANCE INCIDENT REVIEW
// H446 §1.5.1 — Computing legislation:
//   Computer Misuse Act 1990 (S1, S2, S3)
//   Data Protection Act 1998
//   Copyright Designs & Patents Act 1988
//   Regulation of Investigatory Powers Act 2000
// ═══════════════════════════════════════════════════════════
MODULES.legalCompliance = {
  id: 'legalCompliance',
  name: 'LEGAL & COMPLIANCE INCIDENT REVIEW',

  emailSender: ()=>pick(['compliance@company.net','legal@company.net','ciso@company.net','hr-legal@company.net']),
  emailSubject: ()=>pick(['Compliance Review: Reported Incidents Require Legal Assessment','Legal Team: Incident Log — Analyst Classification Needed','CISO Office: Computing Law Incidents Awaiting Triage','HR & Legal: Incident Reports — Legislation Mapping Required']),
  emailBody(){
    return pick([
      `Analyst,\n\nA batch of reported incidents has been escalated to the compliance team. Each requires classification under the relevant computing legislation before we can determine the appropriate response.\n\nLoad the Legal Reference Database. For each incident, identify which law applies and determine the correct action: notify police (criminal offense), report to the ICO (data protection breach), or handle internally (policy violation).\n\nCompliance Team`,
      `Hi,\n\nFollowing advice from our legal team, we're tightening our incident classification process. Several recent reports have been escalated incorrectly — either to the wrong authority or not at all.\n\nPlease review each incident using the Legal Reference Database. Apply the correct legislation: CMA 1990 (S1, S2, S3), DPA 1998, CDPA 1988, or RIPA 2000 as appropriate.\n\nCISO Office`,
      `Analyst,\n\nWe've received a mix of reported incidents this week. Some may constitute criminal offences; others are data protection issues requiring ICO notification; and some are internal matters only.\n\nCorrectly classifying each incident is important — under-reporting a criminal offence is itself a risk, and over-reporting wastes enforcement resources. Use the Legal Reference Database.\n\nLegal & Compliance`
    ]);
  },

  tools: {
    correct: 'Legal Reference Database',
    decoys: ['Packet Capture Analyser','Encryption Audit Tool','SQL Query Log Viewer','Firewall Rule Manager','Process Monitor','Email Header Analyser','Vulnerability Scanner']
  },

  briefing: {
    title: 'Legal & Compliance Incident Review',
    tagline: 'Applying UK computing legislation to real-world security incidents',
    summary: 'Four UK laws govern computing: the Computer Misuse Act 1990 (CMA) criminalises unauthorised computer access — S1: unauthorised access (max 2 years); S2: unauthorised access with intent for further offence (max 5 years); S3: unauthorised acts impairing computer operation, e.g. malware deployment (max 10 years). The Data Protection Act 1998 (DPA) regulates personal data processing. The Copyright Designs and Patents Act 1988 (CDPA) protects software as literary work. The Regulation of Investigatory Powers Act 2000 (RIPA) governs lawful interception of communications.',
    watchFor: 'Unauthorised system access → CMA S1 • Unauthorised access with further intent (e.g. accessing systems to steal data) → CMA S2 • Installing malware, modifying/deleting data without authority → CMA S3 • Personal data processed without consent, shared unlawfully, or retained beyond necessity → DPA 1998 • Copying or distributing software without licence → CDPA 1988 • Intercepting communications without lawful authority → RIPA 2000',
    realWorld: 'The CMA 1990 has been used in prosecutions ranging from a disgruntled employee deleting company files (S3) to a researcher who accessed a company database without authorisation even to expose a vulnerability (S1 — intent is irrelevant). In 2018, Facebook was fined £500,000 (the maximum under DPA 1998) by the ICO for the Cambridge Analytica scandal — demonstrating the DPA\'s enforcement reach. GDPR (2018) superseded and extended DPA 1998 with far higher maximum fines — but the four Acts above remain the foundation of UK computing law.'
  },

  generateScenario({numItems=6}={}){
    const pool = [
      // RED — criminal offences, report to police
      {
        name:'INC-2025-0014', purpose:'Keylogger installed on colleague\'s computer',
        incident:'Employee installed software keylogger on a colleague\'s workstation to capture passwords', legislation:'Computer Misuse Act 1990', section:'Section 3',
        ragAnswer:'R', actionAnswer:'reportPolice',
        notes:'Installing a keylogger without authority constitutes an unauthorised act intended to impair another\'s computer and intercept data — CMA S3 (max 10 years). Report to police. This is not merely a policy issue; it is a criminal offence regardless of whether the perpetrator is an employee.'
      },
      {
        name:'INC-2025-0019', purpose:'Former employee remotely accessed company systems post-termination',
        incident:'Ex-employee used retained credentials to access the CRM database after employment ended', legislation:'Computer Misuse Act 1990', section:'Section 1',
        ragAnswer:'R', actionAnswer:'reportPolice',
        notes:'Accessing a computer system without authorisation — credentials were no longer valid post-termination — is CMA S1 (max 2 years). If the purpose was to extract data for a competitor, it may be S2 (max 5 years). Report to police and preserve evidence. Revoke all remaining access immediately.'
      },
      {
        name:'INC-2025-0022', purpose:'Ransomware deployed by insider threat',
        incident:'Junior system administrator deliberately encrypted file servers and demanded payment', legislation:'Computer Misuse Act 1990', section:'Section 3',
        ragAnswer:'R', actionAnswer:'reportPolice',
        notes:'Deploying ransomware — intentionally modifying computer material without authority to impair its operation — is CMA S3 (max 10 years). This is the most serious category under the CMA. Report to police immediately and engage incident response. Do not pay the ransom.'
      },
      {
        name:'INC-2025-0031', purpose:'Developer accessed production database without authorisation "to investigate a bug"',
        incident:'Developer bypassed access controls and queried the live customer database without approval, claiming they were investigating a performance issue', legislation:'Computer Misuse Act 1990', section:'Section 1',
        ragAnswer:'R', actionAnswer:'reportPolice',
        notes:'Intent does not negate culpability under CMA S1 — the developer accessed a computer system without authorisation. R v Gold & Schifreen (1988) and subsequent CMA cases confirm that "investigating" or "testing" without authority is still unauthorised access. Report to police.'
      },
      {
        name:'INC-2025-0035', purpose:'Employee intercepted manager\'s emails using network monitoring tool',
        incident:'Staff member configured a network tap on the manager\'s VLAN segment to capture their email communications', legislation:'Regulation of Investigatory Powers Act 2000', section:'Section 1',
        ragAnswer:'R', actionAnswer:'reportPolice',
        notes:'Unlawful interception of communications — capturing email content in transit — is an offence under RIPA 2000 S1 regardless of the network owner\'s identity. The employee had no lawful authority for interception. Report to police..'
      },
      // AMBER — regulatory breaches, report to ICO / legal
      {
        name:'INC-2025-0008', purpose:'Customer mailing list sold to marketing company without consent',
        incident:'Marketing manager sold a database of 45,000 customer email addresses to a third-party marketing firm without customer consent', legislation:'Data Protection Act 1998', section:'Principles 1 & 2',
        ragAnswer:'A', actionAnswer:'reportICO',
        notes:'Under DPA 1998, personal data must be processed fairly and lawfully (Principle 1) and only for specified purposes (Principle 2). Selling customer data without consent violates both. Report to the ICO. Customers must be notified. The ICO can issue enforcement notices and, under DPA 1998, fines up to £500,000.'
      },
      {
        name:'INC-2025-0011', purpose:'HR accidentally emailed payroll spreadsheet to all staff',
        incident:'HR administrator sent an email containing all employees\' salaries and NI numbers to the entire company distribution list', legislation:'Data Protection Act 1998', section:'Principle 7',
        ragAnswer:'A', actionAnswer:'reportICO',
        notes:'Accidental disclosure of personal data (salary, NI numbers — "sensitive" under DPA 1998) breaches Principle 7: appropriate security measures must be in place. The ICO must be notified of significant accidental breaches. Affected individuals should be informed. Internal disciplinary action is also appropriate.'
      },
      {
        name:'INC-2025-0026', purpose:'Customer records retained 12 years after contract end',
        incident:'Audit discovered that customer personal data has been retained in the CRM system for 12 years after customers cancelled their accounts — no deletion policy exists', legislation:'Data Protection Act 1998', section:'Principle 5',
        ragAnswer:'A', actionAnswer:'reportICO',
        notes:'DPA 1998 Principle 5: personal data shall not be kept longer than is necessary for the specified purpose. Retaining inactive customer data for 12 years without justification is a clear breach. Report to ICO and implement a data retention and deletion policy immediately.'
      },
      // GREEN — internal policy violations (no criminal/regulatory breach)
      {
        name:'INC-2025-0003', purpose:'Employee installed unlicensed software on their work laptop',
        incident:'IT audit found that an employee had installed unlicensed copies of design software on their company-issued laptop', legislation:'Copyright Designs & Patents Act 1988', section:'CDPA (internal)',
        ragAnswer:'G', actionAnswer:'internal',
        notes:'Installing unlicensed software violates CDPA 1988 and company IT policy, but this is primarily a licensing/policy issue handled internally. Remove unlicensed software, issue formal warning, purchase appropriate licences. Not a criminal referral in the first instance unless wilful large-scale piracy is involved.'
      },
      {
        name:'INC-2025-0007', purpose:'Junior analyst accessed their own employee record in the HR system',
        incident:'Junior analyst queried the HR database to view their own salary record and leave balance — access they are not supposed to have but the data was their own', legislation:'Not a breach', section:'Policy only',
        ragAnswer:'G', actionAnswer:'internal',
        notes:'Accessing your own data is not an offence under the CMA (no intent to harm, own data) or DPA (subject access rights exist). The analyst exceeded their system authorisation but the action caused no harm. Address the access control gap and issue a reminder of acceptable use policy. Internal matter only.'
      },
      {
        name:'INC-2025-0016', purpose:'Graduate trainee tested SQL injection on company\'s own test server',
        incident:'Graduate trainee ran SQL injection payloads against the company\'s own development/test environment as a self-directed learning exercise, with no data exfiltration or damage', legislation:'Internal assessment required', section:'Context-dependent',
        ragAnswer:'G', actionAnswer:'internal',
        notes:'Testing on a company-owned test environment the trainee was authorised to use does not constitute unauthorised access (CMA S1 requires no authorisation). No data was at risk. However, this should have been approved in advance. Agree a responsible disclosure / learning process. Internal matter — no criminal referral.'
      },
    ];
    const nR=pick([1,2,2,3]);
    const nA=pick([1,1,2]);
    const nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Legal, Compliance & HR Department', incorrect:'Network Operations Centre' },
  reportHint: 'Incidents with legal implications need the people who handle law — which team combines legal knowledge with HR?',

  completionText(_,sc){
    const crim=sc.filter(s=>s.ragAnswer==='R').length;
    const reg=sc.filter(s=>s.ragAnswer==='A').length;
    return `<div class="rc info"><h3>LEGAL REVIEW — KEY LEGISLATION</h3>
    <p>${crim} criminal offence(s), ${reg} regulatory breach(es). CMA 1990 S1/S2/S3 = police. DPA 1998 breach = ICO. CDPA/policy violation = internal. RIPA 2000 interception = police.</p>
    <p style="margin-top:8px;"><strong>Key legislation:</strong> Computer Misuse Act 1990 (S1/S2/S3 — unauthorised access to impairment, police), Data Protection Act 1998 (personal data principles, ICO), RIPA 2000 (interception, police), CDPA 1988 (software copyright, internal/civil).</p></div>`;
  },

  actions:{ R:'reportPolice', A:'reportICO', G:'internal' },
  actionLabels:{ reportPolice:'🚨 NOTIFY POLICE', reportICO:'📋 REPORT TO ICO', internal:'📝 INTERNAL REVIEW' },
  ragRules:{
    R:'Criminal offence: CMA 1990 (S1/S2/S3) or RIPA 2000 → NOTIFY POLICE',
    A:'Regulatory breach: Data Protection Act 1998 → REPORT TO ICO',
    G:'Policy/CDPA violation — no criminal element → INTERNAL REVIEW ONLY',
  },

  plenary:{
    reportHint: 'Incidents with legal implications need the people who handle law — which team combines legal knowledge with HR?',
    analogy: 'Classifying incidents under computing law is like triage in A&E: some require immediate escalation to specialist services (police for CMA offences), some need a specific authority (ICO for data protection), and some can be dealt with by the organisation itself (internal disciplinary).',
    whatHappened: 'A range of incidents required classification across four pieces of UK legislation. The key challenge was distinguishing genuinely criminal CMA offences from regulatory DPA breaches, from internal policy matters — and recognising that good intentions (investigating a bug, learning by doing) do not override the law.',
    keyMove: 'CMA S1: unauthorised access (max 2yr). CMA S2: unauthorised access with further intent (max 5yr). CMA S3: impairment of computer / malware (max 10yr). DPA 1998: unlawful personal data processing → ICO. RIPA 2000: unlawful interception → police. CDPA 1988: software piracy → primarily internal.',
    realWorld: 'The ICO fined Facebook £500,000 under DPA 1998 for the Cambridge Analytica scandal — the maximum possible under that Act. GDPR (2018) raised maximum fines to €20 million or 4% of global annual turnover, whichever is higher. The CMA has been used to prosecute cases from teenage hackers to state-sponsored actors. These laws are real, routinely enforced, and directly relevant to any computing career.',
    quiz:[
      {q:'Section 1 of the Computer Misuse Act 1990 criminalises:',options:['Writing malicious software with intent to impair computer systems — maximum 10 years','Unauthorised access to computer material — maximum 2 years','The unlicensed reproduction and distribution of software'],correct:1},
      {q:'Which section of the CMA 1990 would apply to someone who deploys ransomware to encrypt a company\'s file servers?',options:['Section 1 — unauthorised access to computer material','Section 2 — unauthorised access with intent to commit a further offence','Section 3 — unauthorised acts with intent to impair the operation of a computer'],correct:2},
      {q:'The Data Protection Act 1998 is primarily concerned with:',options:['Preventing unauthorised access to government and public sector computer systems','The fair, lawful and proportionate processing of personal data by organisations and individuals','The licensing of commercial software products and the rights of software authors'],correct:1},
      {q:'The Regulation of Investigatory Powers Act 2000 (RIPA) regulates:',options:['The registration and ownership of internet domain names in the UK','The lawful interception of communications and surveillance by public authorities and employers','The licensing of internet service providers to operate in the UK'],correct:1},
      {q:'Under the Copyright Designs and Patents Act 1988, software is protected as:',options:['A patented invention requiring registration with the Intellectual Property Office','An industrial design, giving automatic protection to the user interface','Literary work — the source code is treated as a form of writing with automatic copyright'],correct:2},
      {q:'The maximum prison sentence for a Section 3 CMA offence is:',options:['2 years — the same as Section 1','5 years — as it involves intent to commit further offences','10 years — reflecting the severity of impairing computer systems'],correct:2},
      {q:'An employee accesses a colleague\'s private email account without permission. Under which legislation does this primarily fall?',options:['Data Protection Act 1998 — processing the colleague\'s personal data without consent','Section 1 of the Computer Misuse Act 1990 — unauthorised access to computer material','Copyright Designs and Patents Act 1988 — the email content is literary work'],correct:1},
      {q:'Which organisation would a company notify following a significant accidental personal data breach affecting customers?',options:['The police, under the Computer Misuse Act 1990','The Information Commissioner\'s Office (ICO), under the Data Protection Act 1998','The Home Office, under the Regulation of Investigatory Powers Act 2000'],correct:1},
      {q:'Section 2 of the CMA 1990 differs from Section 1 in that it requires:',options:['That the unauthorised access caused financial damage exceeding £1,000','That the defendant intended to commit or facilitate a further criminal offence','That the defendant was acting as part of an organised criminal group'],correct:1},
    ]
  }
};


// ═══════════════════════════════════════════════════════════
// ENGINE INTEGRATION — Required global definitions
// ═══════════════════════════════════════════════════════════

// MODULE_LIST drives the queue builder in engine.js
// (replaces the original MODULE_LIST from the children's version)
if(typeof MODULE_LIST !== 'undefined'){
  MODULE_LIST.length = 0;
} else {
  var MODULE_LIST = [];
}
['packetAnalysis','encryptionAudit','sqlInjection','firewallReview','legalCompliance']
  .forEach(m => MODULE_LIST.push(m));

// getToolOptions: shuffle correct tool with 2 decoys
function getToolOptions(moduleId){
  const mod=MODULES[moduleId]; if(!mod) return [];
  const decoys=shuffle(mod.tools.decoys).slice(0,2);
  return shuffle([mod.tools.correct,...decoys]);
}

// DATA COLUMN DEFINITIONS — drive the card rendering in engine.js
var MODULE_COLUMNS = {
  packetAnalysis: [
    { key:'name',     label:'FLOW ID' },
    { key:'srcIP',    label:'SOURCE IP' },
    { key:'protocol', label:'PROTOCOL' },
    { key:'dstPort',  label:'DEST PORT' },
    { key:'rate',     label:'PACKET RATE' },
    { key:'flags',    label:'TCP FLAGS' },
  ],
  encryptionAudit: [
    { key:'name',       label:'SYSTEM' },
    { key:'algorithm',  label:'ALGORITHM' },
    { key:'keySize',    label:'KEY / OUTPUT' },
    { key:'useCase',    label:'USE CASE' },
    { key:'lastUpdated',label:'LAST UPDATED' },
  ],
  sqlInjection: [
    { key:'name',           label:'ENDPOINT' },
    { key:'inputField',     label:'INPUT FIELD' },
    { key:'submittedValue', label:'SUBMITTED VALUE' },
    { key:'responseCode',   label:'HTTP RESPONSE' },
  ],
  firewallReview: [
    { key:'name',        label:'CHANGE REQ' },
    { key:'purpose',     label:'DESCRIPTION' },
    { key:'protocol',    label:'PROTOCOL' },
    { key:'port',        label:'PORT(S)' },
    { key:'direction',   label:'DIRECTION' },
  ],
  legalCompliance: [
    { key:'name',        label:'INCIDENT ID' },
    { key:'purpose',     label:'SUMMARY' },
    { key:'legislation', label:'LEGISLATION' },
    { key:'section',     label:'SECTION / PRINCIPLE' },
  ],
};

// ACTION BUTTON DEFINITIONS — referenced by engine.js MODULE_ACTIONS
if(typeof MODULE_ACTIONS === 'undefined'){ var MODULE_ACTIONS = {}; }

MODULE_ACTIONS.packetAnalysis = [
  { id:'block',   label:'🚫 BLOCK SOURCE' },
  { id:'monitor', label:'👁 MONITOR & ALERT' },
  { id:'allow',   label:'✅ ALLOW FLOW' },
];
MODULE_ACTIONS.encryptionAudit = [
  { id:'replace',  label:'🔴 REPLACE URGENTLY' },
  { id:'schedule', label:'🟡 SCHEDULE REPLACEMENT' },
  { id:'maintain', label:'✅ MAINTAIN' },
];
MODULE_ACTIONS.sqlInjection = [
  { id:'block',       label:'🚫 BLOCK & ALERT DBA' },
  { id:'investigate', label:'🔍 FLAG FOR REVIEW' },
  { id:'allow',       label:'✅ ALLOW (LEGITIMATE)' },
];
MODULE_ACTIONS.firewallReview = [
  { id:'reject',   label:'🚫 REJECT' },
  { id:'escalate', label:'🟡 ESCALATE FOR REVIEW' },
  { id:'approve',  label:'✅ APPROVE' },
];
MODULE_ACTIONS.legalCompliance = [
  { id:'reportPolice', label:'🚨 NOTIFY POLICE' },
  { id:'reportICO',    label:'📋 REPORT TO ICO' },
  { id:'internal',     label:'📝 INTERNAL REVIEW' },
];


// ═══════════════════════════════════════════════════════════
// MODULE 6: SOCIAL ENGINEERING ANALYSIS
// Network security threats — human-factor attacks:
// phishing, spear-phishing, pretexting, vishing,
// baiting, CEO fraud (Business Email Compromise)
// ═══════════════════════════════════════════════════════════
MODULES.socialEngineering = {
  id: 'socialEngineering',
  name: 'SOCIAL ENGINEERING ANALYSIS',

  emailSender: ()=>pick(['awareness@secops.internal','security-alerts@company.net','hr-security@company.net','soc@cyberdefence.net']),
  emailSubject: ()=>pick(['Staff Reports: Suspicious Communications Require Triage','Security Awareness Alert: Potential Social Engineering Attempts','Reported Incidents: Human-Factor Attack Triage Required','SOC Alert: Suspicious Contact Attempts — Analyst Review Needed']),
  emailBody(){
    return pick([
      `Analyst,\n\nSeveral staff members have reported suspicious communications over the past 24 hours. Some may be social engineering attempts; others may be legitimate contacts that triggered unnecessary concern.\n\nLoad the Social Engineering Alert Triage tool. For each report, classify the communication and determine the correct response.\n\nRemember: social engineering attacks exploit psychology, not technology. The key indicators are urgency, authority, secrecy and unusual requests.\n\nSecurity Awareness Team`,
      `Hi,\n\nFollowing last month's simulated phishing exercise, staff are now actively reporting suspicious contacts. We need to triage these reports — some are genuine attacks, some are borderline, and some are legitimate business communications wrongly flagged.\n\nUse the Social Engineering Alert Triage tool. Focus on: who is making the request, what they're asking for, and whether the channel and process are appropriate.\n\nSOC Team`,
      `Analyst,\n\nWe've had a cluster of unusual contact attempts in the last 48 hours — possible coordinated social engineering campaign. Please triage each report. The goal is to distinguish genuine attacks from false positives without creating unnecessary operational disruption.\n\nKey question for each: does this request follow the right process through the right channel, or does it bypass normal procedures?\n\nHuman Factor Security`
    ]);
  },

  tools: {
    correct: 'Social Engineering Alert Triage',
    decoys: ['Packet Capture Analyser','Encryption Audit Tool','SQL Query Log Viewer','Firewall Rule Manager','Legal Reference Database','Endpoint Detection Log Viewer','Email Header Analyser']
  },

  briefing: {
    title: 'Social Engineering Analysis',
    tagline: 'Identifying human-factor attacks that bypass technical controls',
    summary: "Social engineering attacks target people rather than systems. They exploit psychological principles: authority (the request comes from someone senior), urgency (act now or face consequences), scarcity (limited time window), social proof (others have already done this), and reciprocity. Phishing uses email; spear-phishing is personalised to the target; vishing uses phone calls; smishing uses SMS. Pretexting builds a fabricated scenario to establish trust. Baiting uses physical media or digital lures. CEO fraud (Business Email Compromise) impersonates executives to authorise fraudulent payments. The defence is always verification through a separate, pre-established channel — not the one the attacker is using.",
    watchFor: 'Requests for credentials, passwords or MFA codes — no legitimate IT team will ask for these • Unusual urgency: "act now or your account will be deleted" • Requests to bypass normal processes or keep the contact secret • Claimed identities that cannot be independently verified • Any request for financial transfers outside normal procurement channels • Unexpected physical access requests to secure areas',
    realWorld: "In 2020, attackers called Twitter's internal IT support, impersonated employees, and convinced staff to hand over admin credentials. Within hours they had compromised 130 high-profile accounts including Barack Obama, Elon Musk and Apple, posting a Bitcoin scam that generated $120,000 in two hours. No malware was used. The entire attack was a phone call."
  },

  generateScenario({numItems=6}={}){
    const pool = [
      // RED — clear social engineering attacks
      {
        name:'SE-001', purpose:'Phone call to IT help desk claiming urgent account issue',
        channel:'Phone', claimedIdentity:'Senior manager (David Hargreaves)', request:'Caller asks IT to reset their password and temporarily disable MFA — says they are locked out before an important board meeting',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Classic vishing attack. Legitimate users reset passwords through self-service portals with identity verification. Requests to disable MFA over the phone are never legitimate. The claimed urgency (board meeting) is a pressure tactic. Block and report.'
      },
      {
        name:'SE-002', purpose:'Email asking for emergency bank transfer',
        channel:'Email', claimedIdentity:'CEO (sent from ceo-company.net — not company.com)', request:'Asks Finance to transfer £18,500 to a new supplier account "urgently and confidentially before the board sees it"',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Business Email Compromise (CEO fraud). The domain is a lookalike — ceo-company.net vs company.com. The combination of financial request, urgency and secrecy ("before the board sees it") are the classic BEC triad. Verify all bank transfer requests by calling the requestor directly on a known number.'
      },
      {
        name:'SE-003', purpose:'Spear-phishing email referencing real internal project',
        channel:'Email', claimedIdentity:'IT Security (it-security@company-support.co.uk)', request:'References the ongoing "Project Meridian" migration by name, asks recipient to click a link and re-authenticate to the new SharePoint environment',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Spear-phishing: the attacker has researched the company and used a real project name to build credibility. The sender domain (company-support.co.uk) is not the company\'s actual domain. The link leads to a credential-harvesting page. The personalisation is the attack — it makes it feel legitimate.'
      },
      {
        name:'SE-004', purpose:'USB drive left in company car park',
        channel:'Physical', claimedIdentity:'Unknown — labelled "Staff Salary Review Q4 2025"', request:'Multiple drives found in car park. One employee plugged one in to find out whose it was.',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Baiting attack: the label exploits curiosity and self-interest. Once plugged in, the drive executes a payload automatically or prompts the user to enable macros. Isolate the affected workstation immediately. Never plug unknown media into a work device — the "I just wanted to return it" instinct is the attack vector.'
      },
      {
        name:'SE-005', purpose:'Contractor requesting server room access without prior arrangement',
        channel:'Physical', claimedIdentity:'Engineer from "Halon Systems Ltd" (fire suppression)', request:'Arrives at reception unannounced, says they need 30-minute access to the server room for an annual safety inspection, shows a business card',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Pretexting with physical tailgating attempt. The scenario creates a plausible cover (fire safety) but no appointment exists and no company badge verification is possible. Legitimate contractors are always pre-booked, escorted and signed in. Deny access, ask them to rebook through Facilities.'
      },
      {
        name:'SE-006', purpose:'LinkedIn message requesting internal technical details',
        channel:'Social Media', claimedIdentity:'Recruiter at competitor firm (profile created 2 weeks ago)', request:'Asks about "technical pain points" with the company\'s current infrastructure and offers a referral bonus for information',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Competitive intelligence gathering / corporate espionage. The new account, unsolicited contact and requests for internal technical detail are the indicators. This is social engineering even without a technical payload — sharing internal infrastructure details aids targeted attacks.'
      },
      // AMBER — suspicious, verify before proceeding
      {
        name:'SE-007', purpose:'Email from "Microsoft" about Azure account suspension',
        channel:'Email', claimedIdentity:'Microsoft Azure Support (azure-alerts@microsoft-cloud-support.com)', request:'States the company\'s Azure subscription will be suspended in 48 hours due to billing issue, requests login to update payment details',
        ragAnswer:'A', actionAnswer:'verify',
        notes:'The sender domain is suspicious (microsoft-cloud-support.com, not microsoft.com) but the message content is plausible. The company does use Azure. Verify directly by logging into portal.azure.com — never via the link in this email. Could be phishing or could be a legitimate notification routed through a third-party billing service.'
      },
      {
        name:'SE-008', purpose:'Help desk ticket asking to whitelist a new software tool',
        channel:'Internal ticketing system', claimedIdentity:'Development team lead', request:'Submitted via official ticketing system, asks IT to whitelist a new open-source dependency analysis tool for the dev team\'s use',
        ragAnswer:'A', actionAnswer:'verify',
        notes:'Submitted through the correct channel (internal ticketing), which reduces risk. However, whitelisting external tools creates a potential supply chain risk. Verify the request is genuine with the development manager, and check whether the tool has been security-reviewed. Not a clear attack but verification is warranted.'
      },
      {
        name:'SE-009', purpose:'SMS claiming to be from company IT about an urgent system alert',
        channel:'SMS', claimedIdentity:'IT Support (unknown number)', request:'Text says: "URGENT: Your work account has been compromised. Reply YES to freeze it immediately or call this number: 0800 XXX XXXX"',
        ragAnswer:'A', actionAnswer:'verify',
        notes:'Smishing (SMS phishing). Company IT does not send account alerts via personal SMS or use freephone numbers for security issues. However, an actual breach notification would also be unusual. Do not reply or call the number — contact IT support through the official internal number instead.'
      },
      // GREEN — legitimate, no action needed
      {
        name:'SE-010', purpose:'Password reset email from company IT portal',
        channel:'Email', claimedIdentity:'IT Help Desk (helpdesk@company.com)', request:'Standard "Your password will expire in 7 days" notification with a link to the internal self-service portal (intranet.company.com/password)',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: correct internal domain, links to the company intranet (not an external site), standard process, no urgency or unusual request. Password expiry notifications from the internal domain with internal portal links are expected. No social engineering indicators.'
      },
      {
        name:'SE-011', purpose:'Procurement: new supplier onboarding form',
        channel:'Email via official procurement system', claimedIdentity:'Procurement team (procurement@company.com)', request:'Automated notification from the procurement system asking the supplier to complete standard due diligence forms via the company\'s supplier portal',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate business process. Sent from the correct internal domain via the official procurement system with a reference number. No requests for credentials or out-of-process payments. This is normal supplier onboarding.'
      },
      {
        name:'SE-012', purpose:'Fire safety inspection — pre-booked visit',
        channel:'Email confirmation + Reception log', claimedIdentity:'Facilities Management', request:'Pre-booked annual fire system inspection, confirmed via email three weeks ago, contractor checked in at reception with photo ID, escorted by Facilities team',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: appointment pre-booked in advance, contractor verified with photo ID, escorted throughout. This is precisely the process that SE-005 (the pretexting attack) was trying to bypass. The contrast is the point — process compliance is the defence.'
      },
    ];
    const nR=pick([1,2,2,3]);
    const nA=pick([1,1,2]);
    const nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Security Awareness & HR Department', incorrect:'Network Operations Centre' },
  reportHint: 'Social engineering attacks exploit people — which team handles human-factor security and staff incidents?',

  completionText(_,sc){
    const att=sc.filter(s=>s.ragAnswer!=='G').length;
    return `<div class="rc info"><h3>SOCIAL ENGINEERING — KEY PRINCIPLES</h3>
    <p>${att} suspicious contact(s) identified. Social engineering bypasses every technical control by targeting the human. The universal defence: <strong>verify through a separate, pre-established channel</strong> — never through the contact method the attacker is using.</p>
    <p style="margin-top:8px;"><strong>Key types:</strong> Phishing (email), spear-phishing (personalised), vishing (phone), smishing (SMS), pretexting (fabricated scenario), baiting (physical lure), BEC (CEO fraud).</p></div>`;
  },

  actions:{ R:'block', A:'verify', G:'allow' },
  actionLabels:{ block:'🚫 BLOCK & REPORT', verify:'🔍 VERIFY INDEPENDENTLY', allow:'✅ LEGITIMATE' },
  ragRules:{
    R:'Clear social engineering: requests credentials, bypasses process, impersonates authority → BLOCK & REPORT',
    A:'Suspicious but unconfirmed: unusual channel or request → VERIFY through separate channel',
    G:'Follows correct process through correct channel → LEGITIMATE',
  },

  plenary:{
    reportHint: 'Social engineering attacks exploit people — which team handles human-factor security and staff incidents?',
    analogy: 'A social engineering attack is like a con artist who does not pick the lock — they convince the security guard to open the door. All the technical security in the world is bypassed the moment someone hands over their credentials on the phone.',
    whatHappened: 'A mix of attack types targeted staff: vishing, BEC/CEO fraud, spear-phishing, physical baiting and pretexting — all using psychological pressure (urgency, authority, secrecy) rather than exploiting technical vulnerabilities. Some legitimate communications were also present, requiring careful distinction.',
    keyMove: 'Verify through a separate channel you control (call the person on a known number, log in directly via a known URL). Urgency + secrecy + unusual request = attack profile. Legitimate IT teams never ask for passwords or MFA codes. Process compliance — pre-booked, verified, escorted — is the physical access defence.',
    realWorld: "The 2020 Twitter hack compromised 130 accounts of world leaders and public figures using only phone calls to Twitter's internal support. No zero-day exploits. No malware. Just a convincing voice on the phone asking the right questions. Over $120,000 was transferred to attackers before Twitter locked all verified accounts.",
    quiz:[
      {q:'Spear-phishing differs from generic phishing in that it:',options:['Uses a phone call rather than an email as the attack vector','Is specifically targeted at an individual or organisation, using researched personal details to appear credible','Involves physically delivering a USB drive or device to the target'],correct:1},
      {q:'Pretexting is best described as:',options:['Sending a large volume of phishing emails hoping some recipients will click','Creating a fabricated but plausible scenario to establish trust and extract information or access','Exploiting a known software vulnerability to gain unauthorised access'],correct:1},
      {q:'Which psychological principle does "Your account will be permanently deleted unless you verify within 24 hours" primarily exploit?',options:['Social proof — most people have already verified their account','Urgency and scarcity — creating time pressure that overrides careful thinking','Reciprocity — the user owes the company their cooperation'],correct:1},
      {q:'Business Email Compromise (BEC/CEO fraud) attacks typically involve:',options:['Injecting malicious code into the company email server','Impersonating a senior executive to authorise fraudulent financial transfers, often using a lookalike domain','Intercepting emails in transit using a man-in-the-middle attack'],correct:1},
      {q:'A caller claims to be from IT support and asks for your password to fix a login issue. The correct response is:',options:['Give the password — IT support are authorised to access all accounts','Refuse — no legitimate IT team will ever ask for a user\'s password','Ask the caller to email the request first, then provide the password by email'],correct:1},
      {q:'Baiting attacks exploit:',options:['Unpatched software vulnerabilities in operating system drivers','Human curiosity or self-interest — e.g. picking up and plugging in a labelled USB drive found in the car park','Weak passwords that can be guessed by an automated tool'],correct:1},
      {q:'The most effective technical and procedural defence against social engineering is:',options:['Installing endpoint antivirus software on all workstations','Blocking all inbound email attachments at the mail gateway','Security awareness training combined with verification procedures — all unusual requests confirmed through a separate, known channel'],correct:2},
      {q:'Vishing uses which attack channel?',options:['Fraudulent emails designed to look like legitimate communications','Voice calls — phone-based social engineering using a plausible pretext','SMS messages containing malicious links or fraudulent instructions'],correct:1},
      {q:'An attacker who follows an authorised employee through a secure door without using their own credentials is performing:',options:['Pretexting — using a fabricated scenario to justify their presence','Tailgating — exploiting courtesy to gain unauthorised physical access','Vishing — the door entry system uses a PIN (voice interaction)'],correct:1},
    ]
  }
};


// ═══════════════════════════════════════════════════════════
// MODULE 7: MALWARE BEHAVIOUR ANALYSIS
// Network security threats — malware types and behaviour:
// ransomware, trojans, keyloggers, worms, spyware, rootkits
// ═══════════════════════════════════════════════════════════
MODULES.malwareAnalysis = {
  id: 'malwareAnalysis',
  name: 'MALWARE BEHAVIOUR ANALYSIS',

  emailSender: ()=>pick(['edr@secops.internal','endpoint@infrasec.net','soc-alerts@company.net','threat-intel@cyberdefence.net']),
  emailSubject: ()=>pick(['EDR Alert: Anomalous Process Behaviour Detected','Endpoint Security: Suspicious Activity Requires Triage','SOC Alert: Potential Malware Indicators on Workstations','Threat Detection: Endpoint Behaviour Review Required']),
  emailBody(){
    return pick([
      `Analyst,\n\nOur Endpoint Detection and Response system has flagged several processes exhibiting unusual behaviour across the estate. Some are confirmed malicious indicators; others may be legitimate system or application activity.\n\nLoad the Endpoint Detection Log Viewer and triage each entry. Focus on: the executable path, what the process is doing, and whether the network connections are expected for that process.\n\nSOC Team`,
      `Hi,\n\nThe EDR platform has raised alerts following scheduled threat hunts across endpoints. We need a second opinion on several flagged processes — some look bad, some are edge cases.\n\nUse the Endpoint Detection Log Viewer. Key question for each: is this process behaviour consistent with its claimed identity and legitimate system operation?\n\nEndpoint Security`,
      `Analyst,\n\nWe received a threat intelligence feed indicating that a malware campaign is targeting organisations in our sector. Running a hunt against that IoC profile has surfaced several process matches — some genuine, some false positives.\n\nTriage each item in the Endpoint Detection Log Viewer. Pay attention to execution paths — legitimate Windows system processes run from known, protected directories.\n\nThreat Intelligence`
    ]);
  },

  tools: {
    correct: 'Endpoint Detection Log Viewer',
    decoys: ['Packet Capture Analyser','Encryption Audit Tool','SQL Query Log Viewer','Firewall Rule Manager','Social Engineering Alert Triage','Legal Reference Database','Network Traffic Monitor']
  },

  briefing: {
    title: 'Malware Behaviour Analysis',
    tagline: 'Identifying malicious process behaviour from endpoint detection logs',
    summary: 'Malware is software designed to disrupt, damage or gain unauthorised access to a system. Key types: a virus attaches to legitimate files and requires user action to spread; a worm self-replicates across a network without user interaction; a trojan appears legitimate but contains malicious functionality; ransomware encrypts files and demands payment; spyware silently collects data; a keylogger captures keystrokes to steal credentials; a rootkit hides its presence by modifying the operating system. Indicators of compromise (IoCs) include: processes running from unexpected paths (Temp folders, AppData), unexpected network connections, high file write rates, and legitimate process names run from wrong directories.',
    watchFor: 'Processes running from C:\\Users\\...\\AppData\\Temp or random-named directories — legitimate system processes run from C:\\Windows\\System32 • A process making outbound connections to non-business IP addresses on a schedule • Rapid file modifications with new extensions appearing (.encrypted, .locked) • PowerShell or cmd.exe launched with -EncodedCommand or -ExecutionPolicy Bypass flags • A known system process name (svchost.exe) running from an unexpected path — process name spoofing • Extremely high disk write rates on a file server',
    realWorld: 'In May 2017 WannaCry ransomware encrypted computers in 150 countries within hours, including approximately one-third of NHS trusts in England. It exploited an unpatched Windows SMB vulnerability (EternalBlue), self-replicated as a worm across networks, then encrypted files and demanded Bitcoin. The NHS cancellations cost an estimated £92 million. The kill switch — a hardcoded domain that WannaCry checked before encrypting — was accidentally discovered by a security researcher who registered it for £8.'
  },

  generateScenario({numItems=6}={}){
    const pool = [
      // RED — confirmed malware behaviour
      {
        name:'svchost_fake.exe', purpose:'Masquerading as Windows system process',
        path:'C:\\Users\\jsmith\\AppData\\Temp\\svchost_fake.exe', behaviour:'Reading all .docx and .xlsx files, writing encrypted copies, high disk I/O (8,000 file writes/min)', connections:'Outbound to 91.108.4.201:443 (not a Microsoft IP)',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Ransomware. Legitimate svchost.exe runs only from C:\\Windows\\System32 — a copy in AppData\\Temp is an immediate red flag (process name spoofing). The high file write rate with new extensions and outbound connection to an external IP (likely C2 server receiving the encryption key) are definitive. Isolate immediately.'
      },
      {
        name:'keylog32.exe', purpose:'Hidden process with keyboard and clipboard access',
        path:'C:\\ProgramData\\WindowsHelper\\keylog32.exe', behaviour:'Hooking keyboard input API (SetWindowsHookEx), reading clipboard contents every 60s, writing to hidden log file', connections:'Outbound to 45.92.14.99:80 every 3 minutes',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Keylogger. SetWindowsHookEx is the Windows API used to intercept all keyboard input. Writing captured data to a hidden file and exfiltrating it via periodic outbound connections is the classic keylogger pattern. The regular interval suggests automated exfiltration. Isolate and preserve the log file as evidence.'
      },
      {
        name:'update_helper.exe', purpose:'Process spreading to network shares',
        path:'C:\\Windows\\Temp\\update_helper.exe', behaviour:'Copying itself to all accessible network shares (\\\\server\\share\\update_helper.exe), creating autorun.inf files, consuming 40% CPU', connections:'Port 445 (SMB) connections to 47 internal hosts in 10 minutes',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Worm. Self-replication to network shares via SMB (port 445) without user interaction is the defining worm behaviour. Autorun.inf files execute the payload automatically when a drive is accessed. The breadth of lateral spread (47 hosts in 10 minutes) indicates it is already propagating. Isolate the source host immediately and check all connected shares.'
      },
      {
        name:'pdf_viewer_pro.exe', purpose:'Trojan with remote access capability',
        path:'C:\\Users\\mwilson\\Downloads\\pdf_viewer_pro.exe', behaviour:'Presents a working PDF viewer UI, simultaneously opening a reverse shell to external IP', connections:'Persistent outbound connection to 203.0.113.42:4444 (known C2 port)',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Trojan horse with remote access (RAT). Port 4444 is a well-known default for Metasploit reverse shells. The process presents as a legitimate PDF viewer (the trojan component) while maintaining a persistent connection to an attacker-controlled server. The user likely downloaded it believing it was genuine software.'
      },
      {
        name:'sysmon_helper.exe', purpose:'Spyware capturing screen and exfiltrating data',
        path:'C:\\ProgramData\\Monitoring\\sysmon_helper.exe', behaviour:'Taking screenshots every 90s, enumerating browser history and saved credentials, compressing output to .zip', connections:'Periodic uploads to cloud storage API (not authorised corporate storage)',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Spyware. Unlike a keylogger (keyboard only), this captures broader intelligence: screenshots, browser history and saved credentials. Exfiltration to unauthorised cloud storage is a data loss indicator. The name (sysmon_helper) mimics the legitimate Sysinternals Sysmon tool — another name spoofing attempt.'
      },
      {
        name:'powershell.exe', purpose:'Encoded PowerShell execution at 03:14',
        path:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', behaviour:'Launched by scheduled task at 03:14 with flags: -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand [base64 string]', connections:'Outbound HTTPS to 104.21.77.33 during execution only',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Malicious PowerShell execution. -ExecutionPolicy Bypass overrides the policy preventing unsigned scripts. -WindowStyle Hidden prevents the user seeing the window. -EncodedCommand is base64-encoded to evade signature detection. Scheduled task at 03:14 minimises visibility. Legitimate scripts do not require these flags. Decode the base64 and investigate.'
      },
      // AMBER — suspicious, requires investigation
      {
        name:'chrome.exe (unusual)', purpose:'Browser process making high-volume API calls',
        path:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', behaviour:'Normal browser process but making 2,000 requests/hour to advertising network APIs — 10× expected rate', connections:'Outbound to multiple ad-network domains',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:'Suspicious but not confirmed malware. The path is legitimate (correct Chrome installation directory). However, the request rate is abnormal — could indicate a malicious browser extension performing ad fraud or cryptojacking. Investigate installed extensions and check for recent installs. The process itself is genuine; the behaviour warrants investigation.'
      },
      {
        name:'wscript.exe', purpose:'Windows Script Host executing VBScript',
        path:'C:\\Windows\\System32\\wscript.exe', behaviour:'Executing a .vbs file from user\'s Downloads folder, which is reading the registry and making network connections', connections:'Outbound to script-delivery.net:80',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:'Suspicious script execution. wscript.exe itself is a legitimate Windows tool, but executing a script from Downloads that accesses the registry and makes network connections is a common malware delivery technique. The domain (script-delivery.net) is not a recognised business destination. Investigate the .vbs file contents.'
      },
      {
        name:'msiexec.exe (silent)', purpose:'Silent MSI package installation',
        path:'C:\\Windows\\System32\\msiexec.exe', behaviour:'Running with /quiet /norestart flags, installing software to C:\\ProgramData\\Tools\\', connections:'Downloaded installer from 185.220.101.28 (non-standard IP)',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:'Potentially unwanted installation. msiexec.exe is the legitimate Windows Installer, but /quiet suppresses the UI and the source IP is not a known software vendor. This could be a legitimate admin deployment or a malicious installer. Verify with the IT team whether this installation was authorised.'
      },
      // GREEN — legitimate system activity
      {
        name:'MsMpEng.exe', purpose:'Windows Defender antivirus scan',
        path:'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\...\\MsMpEng.exe', behaviour:'High CPU (45%), reading all files on C:\\ — scheduled full scan running', connections:'Checking Microsoft threat intelligence feeds (known Microsoft IPs)',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: MsMpEng.exe is the Windows Defender antimalware engine. High CPU during a full scan is expected. The path is a known legitimate location. Connections to Microsoft threat intelligence endpoints are standard behaviour. No action required.'
      },
      {
        name:'wuauclt.exe', purpose:'Windows Update downloading patches',
        path:'C:\\Windows\\System32\\wuauclt.exe', behaviour:'Downloading update packages, writing to C:\\Windows\\SoftwareDistribution\\', connections:'Outbound HTTPS to windowsupdate.microsoft.com (verified Microsoft CDN)',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: wuauclt.exe is the Windows Update agent. Downloading from verified Microsoft CDN addresses and writing to the standard Windows Update cache directory is expected patch management behaviour. Allow.'
      },
      {
        name:'VeeamAgent.exe', purpose:'Backup software reading all files',
        path:'C:\\Program Files\\Veeam\\Endpoint Backup\\VeeamAgent.exe', behaviour:'Reading all files on file server — 4,200 file reads/min during scheduled overnight backup window (02:00–05:00)', connections:'Writing to backup NAS (192.168.10.50) — internal network only',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: this is the Veeam backup agent performing a scheduled nightly backup. High file read rates during the backup window are expected. The destination is an internal NAS appliance, not an external IP. The path is the correct installed location. Allow.'
      },
    ];
    const nR=pick([1,2,2,3]);
    const nA=pick([1,1,2]);
    const nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Incident Response Team', incorrect:'Facilities Management' },
  reportHint: 'Active malware on endpoints is a live security incident — which team handles containment and forensic response?',

  completionText(_,sc){
    const att=sc.filter(s=>s.ragAnswer!=='G').length;
    return `<div class="rc info"><h3>MALWARE ANALYSIS — KEY PRINCIPLES</h3>
    <p>${att} suspicious process(es) identified. Key rule: legitimate Windows system processes run from C:\\Windows\\System32. A known process name running from AppData\\Temp is name spoofing. High file write rate + new extensions = ransomware. Periodic outbound connections to unknown IP = C2 channel.</p>
    <p style="margin-top:8px;"><strong>Key types:</strong> Virus (attaches to files, needs user action), Worm (self-replicates, no user action), Trojan (appears legitimate), Ransomware (encrypts for payment), Keylogger (captures input), Spyware (broad data capture), Rootkit (hides in OS).</p></div>`;
  },

  actions:{ R:'isolate', A:'investigate', G:'allow' },
  actionLabels:{ isolate:'🔴 ISOLATE HOST', investigate:'🔍 INVESTIGATE', allow:'✅ ALLOW (LEGITIMATE)' },
  ragRules:{
    R:'Confirmed malware behaviour: wrong path, C2 connections, mass encryption, self-replication → ISOLATE HOST',
    A:'Suspicious but unconfirmed: unusual behaviour from a legitimate process → INVESTIGATE',
    G:'Expected behaviour for the process and path → ALLOW',
  },

  plenary:{
    reportHint: 'Active malware on endpoints is a live security incident — which team handles containment and forensic response?',
    analogy: 'Analysing EDR logs is like checking CCTV of a building where you know a thief has been. Most people on camera are legitimate — but the thief is using a stolen uniform. You look for people behaving like a thief (going through filing cabinets, copying files) or wearing the uniform wrong (wrong building, wrong floor, wrong time).',
    whatHappened: 'The endpoint estate contained a mixture of active malware (ransomware, keylogger, worm, trojan, spyware, and malicious PowerShell) alongside entirely legitimate system processes exhibiting similar surface-level behaviour (high CPU, file access, network connections). The analysis required understanding what each process should be doing, not just what it is doing.',
    keyMove: 'Wrong path = red flag (svchost.exe should be in System32, not AppData\\Temp). Rapid file modifications + new extensions = ransomware. Self-copying to network shares via SMB = worm. Reverse shell to external IP = trojan/RAT. Regular outbound connections to non-business IP = C2. MsMpEng.exe + high CPU = Defender scan (GREEN).',
    realWorld: "WannaCry (2017) combined a worm's self-replication with ransomware's encryption payload. It spread to roughly 200,000 systems across 150 countries in a single day — including a third of NHS trusts. The kill switch, a single unregistered domain in the malware's code, was discovered and registered for £8, stopping the spread. Endpoint isolation and patching the SMB vulnerability (EternalBlue) were the remediation steps.",
    quiz:[
      {q:'What is the fundamental difference between a worm and a virus?',options:['A virus encrypts files; a worm only monitors network traffic','A worm self-replicates across a network without any user interaction; a virus attaches to files and requires user action (opening the file) to spread','A worm targets mobile devices; a virus targets desktop operating systems'],correct:1},
      {q:'A trojan horse differs from other malware primarily because:',options:['It can only infect systems running Windows operating systems','It presents as a legitimate, useful application while secretly performing malicious actions','It spreads automatically via email attachments without user interaction'],correct:1},
      {q:'Ransomware\'s final visible impact on a victim is typically:',options:['Silently exfiltrating data to an external server over several weeks','Displaying a ransom demand after encrypting the victim\'s files, making them inaccessible','Deleting all files without the possibility of recovery, even after payment'],correct:1},
      {q:'A process named svchost.exe running from C:\\Users\\jsmith\\AppData\\Temp\\ is immediately suspicious because:',options:['svchost.exe is not a valid Windows process name','The legitimate Windows svchost.exe runs only from C:\\Windows\\System32 — any copy elsewhere indicates process name spoofing','All processes in AppData require administrator approval before running'],correct:1},
      {q:'PowerShell launched with -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand flags most likely indicates:',options:['A legitimate administrator running a scheduled maintenance script requiring elevated permissions','Malicious activity: the flags override script signing requirements, hide the window from the user and encode the payload to evade detection','A Windows Update process configuring system policies'],correct:1},
      {q:'Which malware type is specifically designed to intercept and record keyboard input in order to steal credentials?',options:['Spyware — which monitors all user activity including browser history and emails','A keylogger — which focuses specifically on capturing what the user types','A rootkit — which hides the presence of other malware from the operating system'],correct:1},
      {q:'A botnet client on an infected machine would most characteristically show which behaviour in EDR logs?',options:['Extremely high CPU usage continuously, indicating cryptomining','Periodic, scheduled outbound connections to an external IP address on a fixed interval — awaiting instructions from the command and control server','Rapid deletion of system log files to cover its tracks'],correct:1},
      {q:'Spyware differs from a keylogger in that it:',options:['Only targets smartphones and tablet devices, not desktop systems','Captures a broader range of data — screenshots, browser history, saved credentials and clipboard contents — not just keyboard input','Must be installed manually by an attacker with physical access to the device'],correct:1},
      {q:'The WannaCry ransomware spread so rapidly because it combined ransomware behaviour with which other malware capability?',options:['Rootkit functionality — it hid itself from antivirus tools on each infected machine','Worm functionality — it self-replicated across networks by exploiting an SMB vulnerability without any user interaction','Trojan functionality — it disguised itself as a Windows system update'],correct:1},
    ]
  }
};


// ── Update MODULE_LIST to include all 7 modules ───────────────
if(typeof MODULE_LIST !== 'undefined'){
  MODULE_LIST.length = 0;
} else {
  var MODULE_LIST = [];
}
['packetAnalysis','encryptionAudit','sqlInjection','firewallReview','legalCompliance','socialEngineering','malwareAnalysis']
  .forEach(m => MODULE_LIST.push(m));

// ── Column definitions for new modules ───────────────────────
MODULE_COLUMNS.socialEngineering = [
  { key:'name',            label:'CASE ID'     },
  { key:'channel',         label:'CHANNEL'     },
  { key:'claimedIdentity', label:'CLAIMED IDENTITY' },
  { key:'request',         label:'REQUEST / MESSAGE' },
];

MODULE_COLUMNS.malwareAnalysis = [
  { key:'name',        label:'PROCESS'       },
  { key:'path',        label:'EXECUTABLE PATH' },
  { key:'behaviour',   label:'BEHAVIOUR'     },
  { key:'connections', label:'NETWORK ACTIVITY' },
];

// ── Action buttons for new modules ───────────────────────────
MODULE_ACTIONS.socialEngineering = [
  { id:'block',   label:'🚫 BLOCK & REPORT'        },
  { id:'verify',  label:'🔍 VERIFY INDEPENDENTLY'  },
  { id:'allow',   label:'✅ LEGITIMATE'            },
];

MODULE_ACTIONS.malwareAnalysis = [
  { id:'isolate',     label:'🔴 ISOLATE HOST'    },
  { id:'investigate', label:'🔍 INVESTIGATE'     },
  { id:'allow',       label:'✅ ALLOW (LEGITIMATE)' },
];
