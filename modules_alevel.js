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
    return 'Analyst,\n\nWe\'re supporting TechCorp Global\'s incident response. '
      +'Their NIDS captured network traffic during the 72-hour window before the confirmed breach.\n\n'
      +'Triage each flow: some may show the attacker\'s reconnaissance. '
      +'Identifying the initial scan pattern will help us reconstruct the attack timeline and timeline gaps.\n\n'
      +'Time-sensitive — legal counsel need a preliminary report within 4 hours.\n\n'
      +'Incident Response Lead';
  },
  diagnosticSummary:'Network traffic is broken into packets each with a header (source IP, destination IP, port, protocol) and a payload. TCP provides reliable ordered delivery via the three-way handshake SYN then SYN-ACK then ACK. UDP is connectionless and faster with no delivery guarantee. Ports identify services: 80=HTTP, 443=HTTPS, 22=SSH, 53=DNS. Firewalls filter by IP, port and protocol.',
  diagnosticQuestions:[
    {q:'What does TCP stand for',opts:['Transfer Communication Protocol','Transmission Control Protocol','Traffic Control Protocol'],ok:1,hint:'TCP provides reliable ordered delivery confirmed by acknowledgements between sender and receiver.'},
    {q:'What is a network port number used for',opts:['To identify the physical cable in use','To identify which application or service a packet is intended for','To assign a unique address to each device'],ok:1,hint:'Port numbers distinguish services on the same device — 80 for HTTP, 443 for HTTPS, 22 for SSH, 53 for DNS.'},
    {q:'UDP is connectionless. What does this mean',opts:['UDP needs a username to connect','UDP sends data without establishing a connection so delivery is not guaranteed','UDP disconnects automatically after each message'],ok:1,hint:'UDP trades reliability for speed. No handshake, no acknowledgements — useful for streaming where a dropped packet matters less than delay.'},
    {q:'What is a packet in networking',opts:['A bundle of physical cables','A formatted unit of data with a header and payload transmitted over a network','The software that manages network connections'],ok:1,hint:'Messages are split into packets, routed independently and reassembled at the destination. This is packet switching.'},
    {q:'What does DNS do',opts:['Encrypts internet traffic','Translates domain names to IP addresses','Assigns IP addresses to devices on a network'],ok:1,hint:'DNS is the internet address book. Without it you would need the numeric IP address of every website you visit.'},
    {q:'What is bandwidth',opts:['The physical width of a network cable','The maximum rate of data transfer across a network','The number of devices connected to a network'],ok:1,hint:'Bandwidth is measured in bits per second. Higher bandwidth means more data can move per second.'},
    {q:'Port 443 is the default port for which protocol',opts:['HTTP unencrypted web traffic','FTP file transfer','HTTPS encrypted web traffic over TLS'],ok:2,hint:'HTTPS uses port 443. HTTP uses port 80. The S stands for Secure — TLS encryption is applied.'},
    {q:'Packet switching means data',opts:['Travels as one continuous stream down a reserved path','Is broken into packets that may travel different routes and are reassembled at the destination','Can only be sent by one device at a time'],ok:1,hint:'Packet switching is efficient and resilient. Packets can route around failures and network capacity is shared.'},
    {q:'What is a firewall primary role',opts:['To speed up network connections','To monitor and control incoming and outgoing traffic based on rules','To assign IP addresses to devices'],ok:1,hint:'Firewalls permit or deny traffic based on configurable rules covering IP address, port, protocol and direction.'},
    {q:'What does ping measure',opts:['Connection speed in megabits per second','Whether a host is reachable and the round-trip latency in milliseconds','The number of devices on a network'],ok:1,hint:'Ping sends an ICMP echo request. The reply time is latency. No reply means the host is unreachable or blocking ICMP.'},
    {q:'What is the TCP three-way handshake',opts:['SYN then ACK then FIN','SYN then SYN-ACK then ACK','HELLO then READY then GO'],ok:1,hint:'SYN means I want to connect. SYN-ACK means I acknowledge and I also want to connect. ACK means I acknowledge. Connection established.'},
    {q:'What is ICMP primarily used for',opts:['Internal server messaging','Error reporting and network diagnostics such as ping and traceroute','Hardware monitoring'],ok:1,hint:'ICMP is used by ping and traceroute. It reports network errors and allows path analysis.'},
    {q:'A static IP address means',opts:['The address is shared with other devices','The address is permanently assigned and does not change','The address is automatically assigned each session'],ok:1,hint:'Servers need static IPs so clients can reliably find them. Home users typically get dynamic IPs from DHCP.'},
    {q:'What is latency',opts:['The rate at which data is transferred','The delay between sending a request and receiving a response','The number of transmission errors'],ok:1,hint:'Latency is measured in milliseconds. High latency makes real-time applications like video calls feel sluggish.'},
    {q:'What distinguishes a LAN from a WAN',opts:['LANs use wireless WANs use cables','LANs cover a local area such as a building WANs cover larger distances','LANs are public WANs are private'],ok:1,hint:'LAN is Local Area Network covering a building or campus. WAN is Wide Area Network. The internet is a WAN.'},
    {q:'What does a network switch do',opts:['Routes packets between different networks using IP addresses','Connects devices within the same network by forwarding frames using MAC addresses','Blocks unauthorised network access'],ok:1,hint:'Switches learn which device is on which port and send traffic only to the intended recipient.'},
    {q:'What is a proxy server',opts:['A server that stores backup copies of data','An intermediary server that handles requests on behalf of clients allowing filtering logging and caching','A server that assigns IP addresses'],ok:1,hint:'Corporate proxies filter web access, log activity for compliance and cache content to save bandwidth.'},
    {q:'What does half-open connection mean in TCP',opts:['A connection that transmits in one direction only','A SYN received but SYN-ACK not yet acknowledged — server resources allocated but connection incomplete','A connection with reduced bandwidth'],ok:1,hint:'Half-open connections are exploited by SYN flood attacks. The server allocates resources for each SYN — flooding exhausts capacity.'},
    {q:'What is a network protocol',opts:['A document describing hardware specifications','A set of rules governing how data is formatted transmitted and received between devices','Software that physically connects devices'],ok:1,hint:'Protocols ensure devices from different manufacturers communicate reliably. HTTP, TCP, IP, DNS are all protocols.'},
    {q:'A router primary job is to',opts:['Connect devices within the same local network using MAC addresses','Forward packets between different networks using IP addresses','Filter network traffic based on security rules'],ok:1,hint:'Routers operate at the network layer and use IP addresses to determine the best path between different networks.'}
  ],
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

  generateScenario({numItems=6,difficulty=1}={}){
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
    // Adaptive difficulty — set by Analyst Pre-Brief diagnostic score
    var nR,nA,nG;
    if(difficulty===0){           // FOUNDATION: clear-cut cases, minimal edge cases
      nR=pick([2,2,3]); nA=pick([0,0,1]);
    } else if(difficulty===2){    // ADVANCED: edge cases dominate, precision required
      nR=pick([1,1,2]); nA=pick([2,3,3]);
    } else {                      // STANDARD: balanced mix
      nR=pick([1,1,2,2,3]); nA=pick([0,1,1,2]);
    }
    nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Network Security Operations Centre (NSOC)', incorrect:'Human Resources Department' },
  reportHint: 'Packet-level attacks require network-layer containment — which team owns the network perimeter?',

  completionText(_,sc){
    const att=sc.filter(s=>s.ragAnswer!=='G').length;
    const sev=sc.filter(s=>s.ragAnswer==='R').length;
    return `<div class="rc info">
      <div style="font-family:'Orbitron',monospace;font-size:11px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:8px;">📁 TECHCORP IR — NETWORK ANALYSIS</div>
      <p style="margin-bottom:8px;">You identified <strong>${sev} active threat(s)</strong> and ${att-sev} suspicious flow(s) in this capture window. ${sev>0?'These are consistent with the reconnaissance phase of the TechCorp breach — the attacker was mapping the network before moving to exploitation.':'No confirmed attacks in this window — but the suspicious flows warrant monitoring.'}</p>
      <hr style="border-color:rgba(0,255,65,.15);margin:10px 0;">
      <div style="font-family:'Orbitron',monospace;font-size:10px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:6px;">📝 EXAM FOCUS: NETWORKS & SECURITY</div>
      <p style="font-size:12px;line-height:1.6;">Key concepts examiners test: <strong>TCP three-way handshake</strong> (SYN→SYN-ACK→ACK), <strong>SYN flood mechanics</strong> (half-open connections exhaust server), <strong>DNS amplification</strong> (small query → large response), <strong>packet vs circuit switching</strong>, <strong>role of firewalls and proxies</strong>. A 4-mark answer on SYN floods should cover: (1) mechanism, (2) why the server fails, (3) why it\'s hard to filter, (4) one countermeasure.</p>
    </div>`;
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
    
      {q:'What distinguishes a DDoS attack from a DoS attack?',options:['A DDoS uses encrypted traffic to bypass firewalls; a DoS does not','A DoS attack comes from a single source; a DDoS uses many distributed sources — typically a botnet — making it harder to block by IP','A DDoS only targets DNS servers; a DoS can target any service'],correct:1},
      {q:'ICMP is primarily used for:',options:['Transferring files between servers','Error reporting and network diagnostics — for example, ping uses ICMP echo requests','Encrypting data in transit between two hosts'],correct:1},
      {q:'A reverse proxy differs from a forward proxy in that it:',options:['Filters outbound requests on behalf of internal clients','Accepts inbound connections on behalf of servers, masking their internal IP from external clients','Creates a VPN tunnel between two corporate sites'],correct:1},
      {q:'Port 443 is the default port for which protocol?',options:['HTTP — unencrypted web traffic','FTP — file transfer protocol','HTTPS — encrypted web traffic over TLS'],correct:2},
      {q:'In the TCP/IP model, which layer is responsible for end-to-end error checking and flow control?',options:['Network layer — handles IP addressing and routing','Transport layer — TCP provides reliability, ordering and flow control','Application layer — handles protocols such as HTTP and DNS'],correct:1},
      {q:'Why is UDP preferred over TCP for real-time streaming applications?',options:['UDP provides guaranteed delivery, making video frames more reliable','UDP has lower overhead — no connection setup or acknowledgements, so latency is lower even if some packets are lost','UDP automatically encrypts data in transit, protecting the stream from interception'],correct:1},
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
    return 'Analyst,\n\nTechCorp Global processes payments for 500,000 UK customers. '
      +'With a confirmed breach, we need to assess what cryptographic protections were in place — '
      +'and whether any inadequacy contributed to the exposure.\n\n'
      +'The results will determine our ICO notification obligations. '
      +'If customer passwords were stored with broken hashing, or payment data encrypted with deprecated ciphers, '
      +'that materially changes the severity of our disclosure.\n\n'
      +'Load the Encryption Audit Tool and classify each configuration.\n\n'
      +'CISO Support — TechCorp IR';
  },
  diagnosticSummary:'Encryption transforms data using a key. Symmetric uses one shared key such as AES. Asymmetric uses a public and private key pair such as RSA. Hashing produces a fixed-length one-way digest. MD5 and SHA-1 have known weaknesses. bcrypt is designed for password storage because it is deliberately slow. Key length in bits determines resistance to brute-force attacks.',
  diagnosticQuestions:[
    {q:'What does encryption do',opts:['Compresses data for storage','Transforms data into an unreadable form requiring the correct key to reverse','Checks data for errors during transmission'],ok:1,hint:'Encryption provides confidentiality. Only those with the correct key can decrypt and read the data.'},
    {q:'What makes a hash function one-way',opts:['Data can only flow in one direction through the network','The original input cannot be mathematically derived from the hash output alone','A hash can only be applied once to each piece of data'],ok:1,hint:'You can verify a hash by hashing the input again and comparing but you cannot reverse it to recover the original.'},
    {q:'What is symmetric encryption',opts:['The algorithm looks the same forwards and backwards','The same key is used to both encrypt and decrypt','Two parties share equal responsibility for encrypting'],ok:1,hint:'Symmetric encryption such as AES is fast and efficient for bulk data. The challenge is securely sharing the single key.'},
    {q:'AES stands for',opts:['Automated Encryption Standard','Advanced Encryption Standard','Asymmetric Encryption System'],ok:1,hint:'AES is the current industry standard for symmetric encryption. AES-256 with a 256-bit key is the most widely deployed configuration.'},
    {q:'What is a private key in asymmetric encryption',opts:['A key shared privately with selected users','A secret key known only to its owner used to decrypt data encrypted with the corresponding public key','The master key that generates all others'],ok:1,hint:'Anyone can encrypt with the public key but only the private key holder can decrypt. The private key must never be shared.'},
    {q:'RSA is an example of',opts:['Symmetric encryption','A hash function','Asymmetric encryption'],ok:2,hint:'RSA uses mathematically linked public and private keys. It is used for key exchange and digital signatures rather than bulk data encryption.'},
    {q:'A hash function always produces',opts:['Output of variable length depending on input size','A fixed-length output regardless of input size','Output that can be decrypted with the original key'],ok:1,hint:'SHA-256 always produces 256 bits whether the input is one character or one gigabyte. This fixed-length property makes hashes useful as fingerprints.'},
    {q:'What is a rainbow table',opts:['A chart showing algorithm strengths','A precomputed table of hash values used to reverse hash functions and recover passwords','A list of approved encryption algorithms'],ok:1,hint:'Rainbow tables defeat hash functions by precomputing billions of values. Salting makes them impractical.'},
    {q:'What is a salt in password hashing',opts:['A requirement that passwords be longer','A unique random value added to each password before hashing ensuring identical passwords produce different hashes','A secondary encryption layer on the hash'],ok:1,hint:'Without salts identical passwords produce identical hashes which rainbow tables trivially reverse. Unique salts make precomputed attacks impractical.'},
    {q:'Why is MD5 unsuitable for passwords',opts:['MD5 produces hashes that are too short','MD5 is extremely fast to compute enabling rapid brute-force and rainbow table attacks','MD5 is asymmetric and requires two keys'],ok:1,hint:'MD5 can compute billions of hashes per second on modern hardware. Password hashing needs to be deliberately slow — bcrypt and Argon2 are designed for this.'},
    {q:'What is ciphertext',opts:['Text validated as safe to store','Data that has been encrypted and is unreadable without the correct key','Compressed data ready for transmission'],ok:1,hint:'Plaintext is the original readable data. Ciphertext is what encryption produces. Decryption with the correct key reverses the process.'},
    {q:'What is end-to-end encryption',opts:['Data encrypted only at the sending end','Data encrypted from sender to recipient so no intermediary can read it','Encryption applied only at the end of a session'],ok:1,hint:'Even if a message passes through a server the provider cannot read it. Only sender and recipient hold the keys.'},
    {q:'What does a Certificate Authority do',opts:['Encrypts all traffic between client and server','Verifies and digitally signs public keys to establish trust that a key genuinely belongs to who it claims','Generates session keys for HTTPS'],ok:1,hint:'CAs are the trust anchors of HTTPS. Your browser trusts a website because its certificate is signed by a CA your browser already trusts.'},
    {q:'Key length in encryption refers to',opts:['The number of characters in a password','The number of bits in the encryption key — longer keys have exponentially more possible values making brute force harder','The time needed to generate the key'],ok:1,hint:'Doubling key length squares the number of possible keys. 256-bit AES has 2 to the power of 256 possible keys.'},
    {q:'Diffie-Hellman allows',opts:['Two parties to verify each other identity','Two parties to agree on a shared secret key over an insecure channel without transmitting the key itself','A server to generate keys for all its clients'],ok:1,hint:'Diffie-Hellman solved the key distribution problem. TLS uses it so every HTTPS session establishes a unique session key.'},
    {q:'The main advantage of asymmetric over symmetric encryption is',opts:['It is much faster for bulk data','The public key can be distributed freely eliminating the need for a secure channel to share it','It produces shorter ciphertext'],ok:1,hint:'The key distribution problem: how do you securely share a symmetric key? Asymmetric encryption solves this — the public key is public by design.'},
    {q:'What does encrypting data at rest mean',opts:['Encrypting data only during transmission','Encrypting data stored on disk rather than in transit','Archiving data no longer in active use'],ok:1,hint:'Data at rest on disk and data in transit are both threat surfaces. Full-disk encryption protects against physical theft of storage media.'},
    {q:'bcrypt is preferred over SHA-256 for passwords because',opts:['bcrypt produces a longer hash','bcrypt is deliberately slow and computationally expensive resisting brute-force while SHA-256 is fast by design and unsuitable for passwords','bcrypt uses asymmetric encryption'],ok:1,hint:'Work factor is the key concept. bcrypt lets you increase computation cost as hardware improves keeping brute-force expensive even as GPUs get faster.'},
    {q:'What is a digital signature',opts:['An electronic version of a handwritten signature','A cryptographic proof that a message came from who it claims and has not been altered in transit','An encrypted message only the recipient can open'],ok:1,hint:'The sender signs with their private key. Anyone can verify with the public key. Tampering causes verification to fail.'},
    {q:'Why does TLS combine asymmetric and symmetric encryption',opts:['For compatibility with older systems','Asymmetric encryption establishes a shared session key and symmetric encryption then handles data transfer because it is far faster','TLS requires both for legal compliance'],ok:1,hint:'Asymmetric encryption is too expensive for bulk data. TLS uses it only for key exchange then switches to fast AES symmetric encryption.'}
  ],
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

  generateScenario({numItems=6,difficulty=1}={}){
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
    // Adaptive difficulty — set by Analyst Pre-Brief diagnostic score
    var nR,nA,nG;
    if(difficulty===0){           // FOUNDATION: clear-cut cases, minimal edge cases
      nR=pick([2,2,3]); nA=pick([0,0,1]);
    } else if(difficulty===2){    // ADVANCED: edge cases dominate, precision required
      nR=pick([1,1,2]); nA=pick([2,3,3]);
    } else {                      // STANDARD: balanced mix
      nR=pick([1,1,2,2,3]); nA=pick([0,1,1,2]);
    }
    nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Cryptography & Key Management Team', incorrect:'Facilities Management' },
  reportHint: 'Cryptographic vulnerabilities require specialist remediation — which team manages keys and cipher selection?',

  completionText(_,sc){
    const crit=sc.filter(s=>s.ragAnswer==='R').length;
    const weak=sc.filter(s=>s.ragAnswer==='A').length;
    return `<div class="rc info">
      <div style="font-family:'Orbitron',monospace;font-size:11px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:8px;">📁 TECHCORP IR — ENCRYPTION AUDIT</div>
      <p style="margin-bottom:8px;"><strong>${crit} critical finding(s)</strong> and ${weak} scheduled replacement(s). ${crit>0?'These configurations represent real exposure — if customer payment data or passwords were protected by the broken algorithms you identified, the breach severity is significantly higher.':'TechCorp\'s cryptographic posture is better than average — the weakening algorithms identified should still be scheduled for replacement.'}</p>
      <hr style="border-color:rgba(0,255,65,.15);margin:10px 0;">
      <div style="font-family:'Orbitron',monospace;font-size:10px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:6px;">📝 EXAM FOCUS: ENCRYPTION & HASHING</div>
      <p style="font-size:12px;line-height:1.6;">Examiners test: <strong>symmetric vs asymmetric</strong> (one key vs key pair — know when each is used), <strong>hashing is one-way</strong> (cannot decrypt), <strong>why fast hashes fail for passwords</strong> (rainbow tables), <strong>purpose of salting</strong>. Classic 4-mark question: "Explain why MD5 is not suitable for storing passwords" — model answer covers: (1) fast to compute, (2) enables precomputed rainbow table attacks, (3) no salt = identical passwords produce identical hashes, (4) better alternatives exist (bcrypt, Argon2).</p>
    </div>`;
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
    
      {q:'What additional property does AES-GCM provide compared to AES-CBC?',options:['A longer key length, making brute force harder','Authenticated encryption — it simultaneously provides confidentiality AND verifies data integrity','Faster encryption speed for bulk data processing'],correct:1},
      {q:'In TLS (used by HTTPS), why is asymmetric encryption used initially but then replaced by symmetric encryption?',options:['Asymmetric encryption is less secure for large amounts of data','Asymmetric encryption establishes a shared symmetric key — symmetric encryption then handles bulk data because it is far faster','The server requires asymmetric encryption for the session but symmetric for the handshake'],correct:1},
      {q:'What is the purpose of a Certificate Authority (CA)?',options:['To encrypt all traffic between client and server using the CA\'s private key','To verify and digitally sign public keys, establishing trust that a public key genuinely belongs to who it claims to','To generate symmetric encryption keys for HTTPS sessions'],correct:1},
      {q:'What is a hash collision, and why does it matter for security?',options:['When two encryption keys are identical — breaks the confidentiality of the cipher','When two different inputs produce the same hash output — an attacker could substitute a malicious file without detection','When a hash function takes too long to compute — causing denial of service'],correct:1},
      {q:'bcrypt is preferred over SHA-256 for password storage because:',options:['bcrypt produces a longer hash output, making it harder to crack','bcrypt is a deliberately slow algorithm designed to resist brute-force attacks; SHA-256 is fast by design and unsuitable for passwords','bcrypt uses asymmetric encryption; SHA-256 only uses symmetric'],correct:1},
      {q:'What is key stretching (e.g. PBKDF2) used for?',options:['Extending a short encryption key to the required length for the algorithm','Making a password-derived key harder to brute-force by repeatedly applying a hash function thousands of times','Distributing an encryption key securely between two parties'],correct:1},
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
    return 'Analyst,\n\nTechCorp\'s WAF flagged unusual submissions against their payment portal '
      +'in the hours before the breach was confirmed. '
      +'SQL injection against a payment application is a serious initial access vector.\n\n'
      +'If any of these payloads succeeded, it may be how the attacker got in. '
      +'Evidence of exploitation will be critical for both the technical remediation and the legal investigation — '
      +'particularly if customer payment data was accessed.\n\n'
      +'Load the SQL Query Log Viewer and triage each entry.\n\n'
      +'Application Security Lead — TechCorp IR';
  },
  diagnosticSummary:'Relational databases store data in tables with rows and columns. SQL queries retrieve and modify data. SELECT retrieves rows. WHERE filters them. INSERT INTO adds rows. UPDATE modifies rows. DELETE FROM removes rows. DROP TABLE removes the entire table. Primary keys uniquely identify rows. Foreign keys link tables. Parameterised queries separate SQL code from user input preventing injection.',
  diagnosticQuestions:[
    {q:'What does SQL stand for',opts:['Structured Query Language','Secure Query Logic','System Query Library'],ok:0,hint:'SQL is the standard language for relational databases — MySQL, PostgreSQL, SQL Server and others all use it.'},
    {q:'What is a relational database',opts:['A database that connects computers on a network','A database that organises data into linked tables with rows and columns','A database stored entirely in the cloud'],ok:1,hint:'Relational refers to tables linked by relationships defined through keys. This allows complex queries across related datasets.'},
    {q:'What does SELECT * FROM users do',opts:['Creates a new users table','Retrieves every column and row from the users table','Deletes all data from the users table'],ok:1,hint:'SELECT retrieves data. The asterisk means all columns. Without WHERE all rows are returned. SQL injection targets SELECT statements to extract data.'},
    {q:'What is a primary key',opts:['The most important field in a record','A unique identifier for each row that cannot be null and no two rows can share the same value','The administrator password for the database'],ok:1,hint:'Primary keys enforce uniqueness and serve as the reference point for foreign keys in related tables.'},
    {q:'What does the WHERE clause do',opts:['Specifies where data should be stored','Filters rows based on a specified condition','Joins two tables together'],ok:1,hint:'WHERE is the filtering mechanism. SQL injection typically manipulates WHERE conditions to bypass authentication or extract data.'},
    {q:'What is a foreign key',opts:['A key from an external system','A field that references the primary key of another table establishing a relationship between them','An encrypted key protecting sensitive columns'],ok:1,hint:'Foreign keys enforce referential integrity. You cannot insert a value that has no matching primary key in the referenced table.'},
    {q:'What does DELETE FROM do',opts:['Removes the entire database','Removes specific rows matching a condition while keeping the table structure intact','Removes a column from a table'],ok:1,hint:'DELETE without WHERE removes all rows but keeps the table structure. DROP TABLE removes the table itself permanently.'},
    {q:'DROP TABLE removes',opts:['Specific rows matching a condition','The entire table and all its data permanently','Only the table structure leaving data in place'],ok:1,hint:'DROP TABLE is irreversible without a backup. SQL injection achieving DROP TABLE permanently destroys a dataset.'},
    {q:'What is referential integrity',opts:['All data is encrypted in the database','Foreign key values must correspond to valid primary keys in the referenced table preventing orphaned records','Each table must have exactly one primary key'],ok:1,hint:'Referential integrity prevents dangling references — an order cannot reference a customer that does not exist.'},
    {q:'What does UNION do in SQL',opts:['Permanently merges two databases','Combines the results of two SELECT queries into a single result set','Connects to a remote database'],ok:1,hint:'Legitimate use: combining results. SQL injection use: appending attacker-controlled queries to extract data from other tables.'},
    {q:'What is normalisation in database design',opts:['Formatting all data values consistently','Organising data to reduce redundancy and ensure each fact is stored in one place','Compressing the database to save storage'],ok:1,hint:'Normalisation removes duplicate data. First Second and Third Normal Form are the standard levels.'},
    {q:'What does a database transaction ensure',opts:['A financial payment has been authorised','A sequence of operations is treated as a single unit — all complete or none do','A query runs within a time limit'],ok:1,hint:'ACID transactions prevent partial updates. A bank transfer that fails midway rolls back entirely.'},
    {q:'What does ACID stand for',opts:['Access Control Integrity Durability','Atomicity Consistency Isolation Durability','Availability Confidentiality Integrity Distribution'],ok:1,hint:'Atomicity means all-or-nothing. Consistency means valid state is enforced. Isolation means concurrent transactions do not interfere. Durability means committed data persists.'},
    {q:'What does a database index do',opts:['Numbers all tables in order','Speeds up retrieval by allowing the engine to jump directly to matching records without scanning every row','Backs up recently accessed data'],ok:1,hint:'An index on a frequently searched column can reduce query time from seconds to milliseconds on large tables.'},
    {q:'What does INSERT INTO do',opts:['Creates a new table','Adds a new row of data to an existing table','Connects to a database server'],ok:1,hint:'INSERT INTO users adds one row. SQL injection can use INSERT to create unauthorised accounts.'},
    {q:'What is an entity in ER modelling',opts:['A database error to resolve','A real-world object about which data is stored represented as a table','A connection between two servers'],ok:1,hint:'Entities become tables. Customer Order Product are entities. Attributes become columns. Relationships become foreign keys.'},
    {q:'What is the purpose of data validation',opts:['Encrypting data before saving','Ensuring data meets required constraints such as type format and range before being accepted','Verifying the database is running'],ok:1,hint:'Validation is a first line of defence but parameterised queries are still required — validated input can still contain SQL metacharacters.'},
    {q:'What does UPDATE do',opts:['Upgrades the database software','Modifies data in one or more existing rows based on a condition','Restores a table from backup'],ok:1,hint:'UPDATE without WHERE modifies every row — a common accidental data destruction scenario. Always include WHERE when targeting specific records.'},
    {q:'What is a stored procedure',opts:['A backup procedure for the database','A named precompiled SQL block stored in the database that applications call by name','A log of all queries executed'],ok:1,hint:'Stored procedures reduce injection risk because applications call a procedure name with parameters rather than building raw SQL strings.'},
    {q:'What makes a query vulnerable to SQL injection',opts:['The query uses the SELECT command','User input is directly concatenated into the query string without separation between code and data','The database is stored on a public server'],ok:1,hint:'When user input is embedded in SQL code the attacker can modify the query structure. Parameterised queries fix this structurally.'}
  ],
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

  generateScenario({numItems=6,difficulty=1}={}){
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
        endpoint:'/api/v2/products', inputField:'id', submittedValue:"1 UNION SELECT username, pwd_hash FROM users --",
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
    // Adaptive difficulty — set by Analyst Pre-Brief diagnostic score
    var nR,nA,nG;
    if(difficulty===0){           // FOUNDATION: clear-cut cases, minimal edge cases
      nR=pick([2,2,3]); nA=pick([0,0,1]);
    } else if(difficulty===2){    // ADVANCED: edge cases dominate, precision required
      nR=pick([1,1,2]); nA=pick([2,3,3]);
    } else {                      // STANDARD: balanced mix
      nR=pick([1,1,2,2,3]); nA=pick([0,1,1,2]);
    }
    nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Application Security & DBA Team', incorrect:'Marketing Department' },
  reportHint: 'SQL injection targets the database layer — which team owns application security and database administration?',

  completionText(_,sc){
    const att=sc.filter(s=>s.ragAnswer==='R').length;
    return `<div class="rc info">
      <div style="font-family:'Orbitron',monospace;font-size:11px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:8px;">📁 TECHCORP IR — WAF LOG ANALYSIS</div>
      <p style="margin-bottom:8px;"><strong>${att} injection attempt(s)</strong> identified in this capture window. ${att>0?'Any successful injection against TechCorp\'s payment portal could represent the initial access vector for the entire breach. Parameterised queries on every endpoint would have prevented all of these.':'No confirmed injection in this window — though the suspicious probes indicate the attacker was testing input handling.'}</p>
      <hr style="border-color:rgba(0,255,65,.15);margin:10px 0;">
      <div style="font-family:'Orbitron',monospace;font-size:10px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:6px;">📝 EXAM FOCUS: DATABASES & SQL SECURITY</div>
      <p style="font-size:12px;line-height:1.6;">Examiners test: <strong>how SQL injection works</strong> (user input modifies query structure), <strong>parameterised queries as the fix</strong> (code and data separated structurally), <strong>SQL syntax</strong> (SELECT/WHERE/DROP/UNION), <strong>database concepts</strong> (primary/foreign keys, normalisation, ACID). A 6-mark "explain" question on SQL injection typically expects: mechanism, example, why it succeeds, the defence, and why the defence works.</p>
    </div>`;
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
    
      {q:'What does the following SQL return?\nSELECT * FROM users WHERE username = \'admin\' AND active = 1',options:['Every row in the users table','All columns for rows where username is admin and the account is active','Deletes the admin user from the users table'],correct:1},
      {q:'Which SQL command would retrieve the name and salary of every employee earning over £30,000?',options:['SELECT name, salary FROM employees WHERE salary > 30000','GET name, salary FROM employees IF salary > 30000','FIND name, salary IN employees WHERE salary ABOVE 30000'],correct:0},
      {q:'What is referential integrity in a relational database?',options:['All data in the database is encrypted and cannot be accessed without the correct key','Foreign key values must correspond to a valid primary key in the referenced table — preventing orphaned records','Each table has exactly one primary key column'],correct:1},
      {q:'A database in Third Normal Form (3NF) is designed to eliminate:',options:['Duplicate primary keys across tables','Transitive dependencies — every non-key attribute must depend only on the primary key, not on other non-key attributes','Tables with more than three columns'],correct:1},
      {q:'The SQL command DELETE FROM orders WHERE order_id = 42 differs from DROP TABLE orders in that it:',options:['Removes one row while preserving the table structure; DROP removes the table and all data permanently','Is reversible with an UNDO command; DROP is permanent','Requires administrator privileges; DROP can be executed by any user'],correct:0},
      {q:'What does ACID stand for in database transaction processing, and why does it matter for a payment system?',options:['Access, Control, Integrity, Durability — ensures only authorised users can run transactions','Atomicity, Consistency, Isolation, Durability — ensures payment transactions either complete fully or not at all, preventing partial transfers','Availability, Confidentiality, Integrity, Distribution — the core security properties of a database'],correct:1},
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
    return 'Analyst,\n\nTechCorp\'s change management system shows firewall rule requests '
      +'submitted in the 48 hours before the breach. At least one looks suspicious — '
      +'it may have been submitted by the attacker to create an access pathway, '
      +'or by a compromised insider.\n\n'
      +'Any change that should have been rejected represents a control failure. '
      +'We need to identify exactly what was approved, what should have been escalated, '
      +'and what gave the attacker their foothold.\n\n'
      +'Load the Firewall Rule Manager.\n\n'
      +'Change Advisory Board — TechCorp IR';
  },
  diagnosticSummary:'Firewalls filter traffic by protocol, port, direction and IP. Key ports: 22 SSH, 80 HTTP, 443 HTTPS, 3389 RDP, 3306 MySQL. Principle of least privilege means granting only minimum access needed. A DMZ places public-facing servers between internet and internal network. CIDR /32=one IP, /24=256 IPs, /0=all IPs. Implicit deny means anything not explicitly permitted is blocked.',
  diagnosticQuestions:[
    {q:'What is a firewall primary function',opts:['To speed up internet connections','To monitor and filter network traffic based on security rules','To encrypt all data on the network'],ok:1,hint:'Firewalls are gatekeepers. They permit or deny traffic based on rules — anything not matching a permit rule should be blocked.'},
    {q:'What is a network port',opts:['A physical socket on a switch','A logical endpoint identified by a number distinguishing different services on the same device','An opening in the firewall allowing all traffic'],ok:1,hint:'Well-known ports (0-1023) are reserved for standard services. Port numbers route incoming traffic to the correct application.'},
    {q:'What does inbound traffic mean',opts:['Traffic from the local device going out','Traffic arriving at the network from an external source','Traffic circulating within the internal network'],ok:1,hint:'Inbound is traffic arriving. Outbound is traffic leaving. Firewall rules typically restrict inbound more strictly.'},
    {q:'What does the principle of least privilege mean',opts:['New staff receive minimum pay during probation','Users and systems should have only the minimum access rights necessary for their function','Less-used systems should have the most restrictive settings'],ok:1,hint:'Least privilege minimises the blast radius of a compromise. A breached account with minimal permissions causes minimal damage.'},
    {q:'What is a DMZ in networking',opts:['A restricted zone in a server room','A network segment between the internet and internal network hosting public-facing services','A type of guest wireless network'],ok:1,hint:'The DMZ allows web servers to be internet-accessible without exposing internal systems. A compromised DMZ host cannot directly reach internal databases.'},
    {q:'What does 0.0.0.0/0 mean in a firewall rule',opts:['No traffic is permitted','The entire internet — every possible source IP address','Only the local subnet'],ok:1,hint:'CIDR /0 means zero bits are fixed — it matches all addresses. A rule permitting 0.0.0.0/0 opens access from the entire internet.'},
    {q:'What does SSH (port 22) allow',opts:['Sharing files between computers','Encrypted remote command-line access to a server','Sending encrypted email between servers'],ok:1,hint:'SSH is how administrators manage servers remotely. Port 22 exposed to the internet invites brute-force attacks.'},
    {q:'What is a stateful firewall',opts:['A firewall that stores user credentials','A firewall that tracks connection state permitting return traffic for established connections','A firewall that remembers connected user names'],ok:1,hint:'Stateful inspection tracks which connections are legitimate. Return packets are permitted automatically without needing explicit inbound rules.'},
    {q:'What does implicit deny mean',opts:['Traffic is encrypted when no matching rule exists','Any traffic not explicitly permitted by a rule is blocked by default','Peak-hour traffic is automatically denied'],ok:1,hint:'Implicit deny is the foundation of secure firewall design. Rules explicitly permit what is needed — everything else is blocked.'},
    {q:'What is RDP (port 3389) used for',opts:['Routing data between networks','Remotely controlling a computer desktop interface','Encrypting database connections'],ok:1,hint:'RDP exposed to the internet is one of the most common ransomware entry points. Attackers brute-force RDP credentials then deploy ransomware.'},
    {q:'What is network segmentation',opts:['Dividing a network cable into sections','Dividing a network into isolated zones to limit lateral movement after a compromise','Allocating bandwidth evenly across devices'],ok:1,hint:'Segmentation is defence-in-depth. A compromised device in one zone cannot freely reach servers in another.'},
    {q:'What does NAT do',opts:['Translates domain names to IP addresses','Maps private internal IP addresses to a public IP allowing multiple devices to share one public address','Encrypts IP packets in transit'],ok:1,hint:'NAT hides internal IP addresses as a side effect. External observers see only the public IP not which internal device sent the traffic.'},
    {q:'Why is Telnet insecure',opts:['It is too slow for modern networks','It transmits all data including passwords in plaintext making credentials easy to intercept','It requires a dedicated hardware certificate'],ok:1,hint:'Telnet was designed before security was a priority. SSH was created to replace it with encrypted communication.'},
    {q:'An IPS differs from an IDS in that',opts:['An IPS only detects while an IDS blocks','An IPS actively blocks detected malicious traffic while an IDS only alerts and logs','An IPS works at layer 7 while an IDS works at layer 3'],ok:1,hint:'IDS means detect and alert. IPS means detect and prevent. IPS is placed inline in the traffic path.'},
    {q:'What does a WAF do',opts:['A firewall that only protects websites','A firewall that inspects HTTP/S content for application-layer attacks such as SQL injection','A firewall built into a web browser'],ok:1,hint:'A WAF operates at layer 7 analysing web request content. It can block SQL injection and XSS that network firewalls cannot see.'},
    {q:'What does CIDR /24 mean',opts:['24 devices are allowed through the firewall','The first 24 bits are fixed giving a subnet of 256 addresses','24 ports are open on the target'],ok:1,hint:'CIDR /24 = 256 IPs. /32 = one specific IP. /16 = 65536 IPs. /0 = all IPs. Understanding CIDR is essential for evaluating firewall rules.'},
    {q:'What is a VPN',opts:['A network using virtual machines only','An encrypted tunnel for secure communication over an untrusted network','A private network with no internet connection'],ok:1,hint:'VPNs create an encrypted tunnel. Data inside looks like gibberish to any observer. Used for remote access and connecting offices securely.'},
    {q:'What is a proxy server used for in a corporate network',opts:['To back up browsing data','To handle outbound requests on behalf of clients enabling filtering logging and caching','To assign IP addresses to devices'],ok:1,hint:'Corporate proxies filter web access, block malicious sites, log activity for compliance and cache content to save bandwidth.'},
    {q:'What does outbound filtering achieve',opts:['Blocks all data leaving the network','Restricts what data can leave the network helping detect data exfiltration and malware C2 traffic','Filters spam from outbound email only'],ok:1,hint:'Outbound filtering catches malware calling home to C2 servers and employees exfiltrating data.'},
    {q:'What is port 3306 associated with',opts:['RDP Remote Desktop Protocol','MySQL database server','SMTP email sending'],ok:1,hint:'MySQL uses port 3306. Database servers should only accept connections from the application server on the same internal network.'}
  ],
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

  generateScenario({numItems=6,difficulty=1}={}){
    const pool = [
      // RED — reject immediately
      {
        name:'CR-2025-0041', purpose:'Allow ALL inbound TCP port 22 (SSH) from internet', service:'SSH (port 22)', source:'0.0.0.0/0 — any internet IP',
        protocol:'TCP', port:'22', direction:'Inbound', requestedBy:'Dev Team', justification:'Remote server management',
        ragAnswer:'R', actionAnswer:'reject',
        notes:'Exposing SSH (port 22) to 0.0.0.0/0 (the entire internet) creates an enormous attack surface for brute-force and credential stuffing attacks. Reject. Proper practice: restrict SSH access to specific known admin IP ranges, or require VPN access first.'
      },
      {
        name:'CR-2025-0044', purpose:'Allow inbound TCP port 3389 (RDP) from 0.0.0.0/0', service:'RDP (port 3389)', source:'0.0.0.0/0 — any internet IP',
        protocol:'TCP', port:'3389', direction:'Inbound', requestedBy:'IT Support', justification:'Remote desktop access for support',
        ragAnswer:'R', actionAnswer:'reject',
        notes:'RDP exposed to the internet is one of the most commonly exploited configurations — used in ransomware attacks including WannaCry and NotPetya. Reject. Require VPN + MFA before any internal RDP is accessible, never expose port 3389 directly.'
      },
      {
        name:'CR-2025-0047', purpose:'Allow outbound TCP port 23 (Telnet) to any destination', service:'Telnet (port 23)', source:'Any destination',
        protocol:'TCP', port:'23', direction:'Outbound', requestedBy:'Legacy Systems Team', justification:'Connection to legacy router management',
        ragAnswer:'R', actionAnswer:'reject',
        notes:'Telnet transmits all data — including credentials — in plaintext. It was superseded by SSH in 1995. Reject and require migration to SSH for all remote management. This is not a timing issue; Telnet should never be used.'
      },
      {
        name:'CR-2025-0053', purpose:'Allow outbound TCP 0–65535 (all ports) from Finance workstations', service:'All ports (0–65535)', source:'Finance workstations',
        protocol:'TCP', port:'0–65535', direction:'Outbound', requestedBy:'Finance Manager', justification:'Application accessing various cloud services',
        ragAnswer:'R', actionAnswer:'reject',
        notes:'Permitting all outbound ports from Finance workstations would allow malware on those machines to contact any C2 server on any port — and would permit data exfiltration on non-standard ports. Reject. Request a specific list of destination services and open only those ports.'
      },
      // AMBER — escalate for further review
      {
        name:'CR-2025-0038', purpose:'Allow inbound HTTPS (443) from subnet 192.168.50.0/24 to app server', service:'HTTPS (port 443)', source:'192.168.50.0/24 (internal)',
        protocol:'TCP', port:'443', direction:'Inbound', requestedBy:'App Team', justification:'Internal app team testing new microservice',
        ragAnswer:'A', actionAnswer:'escalate',
        notes:'HTTPS on port 443 to a specific internal subnet is lower risk than internet-facing, but the justification lacks specifics: which app server? What microservice? When does this expire? Escalate to confirm the source subnet, destination, and add an expiry date. Not automatically safe without these details.'
      },
      {
        name:'CR-2025-0049', purpose:'Allow outbound TCP 8080 from developer workstations to any', service:'HTTP alt (port 8080)', source:'Developer workstations',
        protocol:'TCP', port:'8080', direction:'Outbound', requestedBy:'Development Lead', justification:'Developer tools and API testing',
        ragAnswer:'A', actionAnswer:'escalate',
        notes:'Port 8080 is a common alternative HTTP port used by development tools. The destination ("any") is too broad — this could be scoped to specific development environments. Escalate to determine if destination can be restricted. Not an immediate reject, but needs tightening.'
      },
      {
        name:'CR-2025-0055', purpose:'Allow inbound TCP 5900 (VNC) from 10.20.0.0/16 to server farm', service:'VNC (port 5900)', source:'10.20.0.0/16 (65,536 IPs)',
        protocol:'TCP', port:'5900', direction:'Inbound', requestedBy:'Systems Administrator', justification:'Remote server console access from management VLAN',
        ragAnswer:'A', actionAnswer:'escalate',
        notes:'VNC on port 5900 from a /16 internal subnet (/16 = 65,536 addresses). The management VLAN access is plausible, but the scope is too wide. Escalate: can this be restricted to specific admin host IPs? VNC access to servers should require strong authentication.'
      },
      // GREEN — approve
      {
        name:'CR-2025-0033', purpose:'Allow inbound HTTPS (443) to web server in DMZ from internet', service:'HTTPS (port 443)', source:'Internet → DMZ web server',
        protocol:'TCP', port:'443', direction:'Inbound', requestedBy:'Web Team', justification:'Public-facing web application requires HTTPS access',
        ragAnswer:'G', actionAnswer:'approve',
        notes:'Standard configuration for a public web server in the DMZ. HTTPS on port 443 is the expected protocol. Web servers in the DMZ are designed to accept inbound internet connections — this is the intended network architecture. Approve.'
      },
      {
        name:'CR-2025-0036', purpose:'Allow outbound HTTPS (443) from internal hosts to Microsoft Update servers', service:'HTTPS (port 443)', source:'Internal → Microsoft CDN',
        protocol:'TCP', port:'443', direction:'Outbound', requestedBy:'IT Infrastructure', justification:'Windows Update and Microsoft 365 traffic',
        ragAnswer:'G', actionAnswer:'approve',
        notes:'Outbound HTTPS to Microsoft Update CDN addresses is standard and required for patch management. Well-documented, specific destination, legitimate business justification. Approve.'
      },
      {
        name:'CR-2025-0039', purpose:'Allow outbound UDP 53 (DNS) to company DNS servers only', service:'DNS (port 53)', source:'Internal → managed resolvers',
        protocol:'UDP', port:'53', direction:'Outbound', requestedBy:'Network Team', justification:'DNS queries from internal hosts to managed resolvers',
        ragAnswer:'G', actionAnswer:'approve',
        notes:'Restricting DNS queries to company-managed resolvers (rather than allowing DNS to any external server) is a security best practice — it prevents DNS tunnelling to arbitrary external servers. Tightly scoped and justified. Approve.'
      },
      {
        name:'CR-2025-0042', purpose:'Allow inbound SMTP (25) to mail relay in DMZ from internet', service:'SMTP (port 25)', source:'Internet → DMZ mail relay',
        protocol:'TCP', port:'25', direction:'Inbound', requestedBy:'Email Infrastructure', justification:'Inbound email delivery from external mail servers',
        ragAnswer:'G', actionAnswer:'approve',
        notes:'A mail relay in the DMZ accepting inbound SMTP on port 25 from the internet is standard email infrastructure. The relay should be isolated in the DMZ and forward only to the internal mail server. This is expected and correctly scoped. Approve.'
      },
    ];
    // Adaptive difficulty — set by Analyst Pre-Brief diagnostic score
    var nR,nA,nG;
    if(difficulty===0){           // FOUNDATION: clear-cut cases, minimal edge cases
      nR=pick([2,2,3]); nA=pick([0,0,1]);
    } else if(difficulty===2){    // ADVANCED: edge cases dominate, precision required
      nR=pick([1,1,2]); nA=pick([2,3,3]);
    } else {                      // STANDARD: balanced mix
      nR=pick([1,1,2,2,3]); nA=pick([0,1,1,2]);
    }
    nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Security Architecture Team', incorrect:'Human Resources Department' },
  reportHint: 'Firewall misconfiguration is a network architecture risk — which team owns security design decisions?',

  completionText(_,sc){
    const rej=sc.filter(s=>s.ragAnswer==='R').length;
    const esc=sc.filter(s=>s.ragAnswer==='A').length;
    return `<div class="rc info">
      <div style="font-family:'Orbitron',monospace;font-size:11px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:8px;">📁 TECHCORP IR — CHANGE REQUEST AUDIT</div>
      <p style="margin-bottom:8px;"><strong>${rej} rule(s) should have been rejected</strong>, ${esc} escalated for further review. ${rej>0?'At least one of these approved changes may have given the attacker their initial network foothold — this is a control failure that will feature in the post-incident report.':'The change management process held up — but several requests needed tighter scoping.'}</p>
      <hr style="border-color:rgba(0,255,65,.15);margin:10px 0;">
      <div style="font-family:'Orbitron',monospace;font-size:10px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:6px;">📝 EXAM FOCUS: FIREWALLS, PROXIES & NETWORK SECURITY</div>
      <p style="font-size:12px;line-height:1.6;">Examiners test: <strong>stateless vs stateful firewalls</strong> (packet filter vs connection tracking), <strong>DMZ architecture</strong> (why public-facing services are separated), <strong>principle of least privilege</strong>, <strong>proxies vs firewalls</strong> (what each controls). A common 4-mark question: "Explain the role of a DMZ in network security" — model answer: (1) subnetwork between internet and internal network, (2) hosts public-facing services, (3) limits blast radius if server is compromised, (4) traffic must be explicitly permitted inward.</p>
    </div>`;
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
    
      {q:'What is implicit deny in a firewall ruleset?',options:['Traffic from unknown IP addresses is automatically encrypted','Any traffic not explicitly permitted by a rule is blocked by default — the firewall denies unless told to allow','The firewall denies all traffic during peak hours to prevent overload'],correct:1},
      {q:'How does network segmentation improve security?',options:['It encrypts all traffic between network segments automatically','It limits lateral movement — if one segment is compromised, the attacker cannot freely access other segments','It doubles the number of available IP addresses on the network'],correct:1},
      {q:'An intrusion prevention system (IPS) differs from an intrusion detection system (IDS) in that it:',options:['Detects attacks and logs them for later analysis; IDS does not detect attacks','Actively blocks detected malicious traffic; an IDS only alerts — it does not take action','Operates at the application layer; IDS operates at the network layer'],correct:1},
      {q:'What is NAT (Network Address Translation) and what incidental security benefit does it provide?',options:['NAT encrypts IP packets in transit, preventing eavesdropping on internal communications','NAT maps private internal IP addresses to a public IP — as a side effect, internal IP addresses are hidden from external networks','NAT automatically blocks all inbound connections, functioning as a basic firewall'],correct:1},
      {q:'Why is Telnet (port 23) considered a critical security risk for server management?',options:['Telnet is too slow for modern high-bandwidth networks, causing timeouts','Telnet transmits all data including passwords in plaintext — any network observer can capture credentials','Telnet requires a dedicated hardware certificate that most servers no longer support'],correct:1},
      {q:'A web application firewall (WAF) differs from a network firewall in that it:',options:['Operates at a higher network layer and inspects HTTP traffic content, including request parameters, for attack signatures','Operates at the network layer and filters by IP address and port only','Only works for HTTPS traffic; network firewalls handle all protocols'],correct:0},
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
    return 'Analyst,\n\nWith TechCorp Global\'s breach confirmed, legal are under immediate pressure. '
      +'The DPA 1998 notification obligation to the ICO runs from the point of awareness — '
      +'that clock is already ticking.\n\n'
      +'We need each incident classified correctly: criminal offences to the police under the CMA, '
      +'data protection breaches to the ICO, policy violations handled internally. '
      +'Misclassifying a criminal act as an internal matter is itself a serious liability.\n\n'
      +'Load the Legal Reference Database.\n\n'
      +'Legal Director — TechCorp Global';
  },
  diagnosticSummary:'Four UK Acts. Computer Misuse Act 1990 (CMA) is criminal: Section 1 unauthorised access 2 years max, Section 2 access with intent 5 years, Section 3 impairment and malware 10 years. Data Protection Act 1998 (DPA) is regulatory enforced by the ICO. CDPA 1988 covers software copyright. RIPA 2000 covers interception of communications and is criminal. CMA and RIPA go to police. DPA goes to ICO.',
  diagnosticQuestions:[
    {q:'What does CMA stand for',opts:['Computer Management Act','Computer Misuse Act','Cybercrime and Misconduct Act'],ok:1,hint:'The Computer Misuse Act 1990 is the primary UK criminal law covering unauthorised access to computer systems.'},
    {q:'What is the ICO',opts:['The International Computing Organisation','The Information Commissioner Office — the UK data protection regulator','The Internet Content Oversight authority'],ok:1,hint:'The ICO enforces the DPA and GDPR in the UK. It can investigate complaints, issue enforcement notices and impose fines.'},
    {q:'What is unauthorised access under the CMA',opts:['Accessing a computer without knowing the password','Accessing a computer system without permission from its owner or operator','Accessing a computer outside working hours'],ok:1,hint:'The CMA does not require malicious intent for Section 1. Simply accessing without permission is a criminal offence.'},
    {q:'What is personal data under UK law',opts:['Any data stored on a personal device','Any information relating to an identified or identifiable living individual','Data a person has created themselves'],ok:1,hint:'Personal data includes names, email addresses, IP addresses and location data — anything that directly or indirectly identifies a living person.'},
    {q:'What distinguishes criminal from civil law',opts:['Criminal covers minor offences civil covers serious ones','Criminal law involves the state prosecuting wrongdoing civil law involves disputes between private parties','Civil applies to businesses criminal applies to individuals'],ok:1,hint:'Criminal prosecution can result in imprisonment. The CMA creates criminal offences prosecuted by the state.'},
    {q:'What does the CDPA protect',opts:['The right to copy published works for personal use','Creators exclusive rights over original works including software as a literary work','A fee paid for commercial content use'],ok:1,hint:'CDPA 1988 treats software as a literary work. Copying distributing or modifying without a licence is copyright infringement.'},
    {q:'What does DPA Principle 1 require',opts:['Data must be deleted after 30 days','Data must be processed lawfully fairly and transparently','Data must be stored only in the UK'],ok:1,hint:'The DPA 1998 has eight principles. Principle 1 (lawful and fair) and Principle 5 (not kept longer than necessary) appear most often in exam scenarios.'},
    {q:'What is a data breach',opts:['A hacker accessing government systems','A security incident where protected data is accessed disclosed or destroyed without authorisation','When a database backup fails'],ok:1,hint:'Data breaches include accidental disclosure, theft of a laptop and misconfigured cloud storage — not just hacking.'},
    {q:'What does RIPA regulate',opts:['Remote access to company computers','The interception of communications in transit','The retention of personal data'],ok:1,hint:'RIPA 2000 covers lawful interception. Monitoring employee emails without proper authority may breach RIPA even if the employer owns the system.'},
    {q:'CMA Section 3 covers',opts:['Accessing a computer without permission','Accessing with intent to commit further offences','Unauthorised acts that impair or disrupt computer systems including deploying malware — maximum 10 years'],ok:2,hint:'S3 carries the heaviest sentence reflecting the severity of attacks that destroy data, install malware or disrupt critical infrastructure.'},
    {q:'Which body handles criminal CMA offences',opts:['The ICO','The police and Crown Prosecution Service','The FCA'],ok:1,hint:'CMA offences are crimes investigated by the police and prosecuted by the CPS. The ICO handles DPA regulatory breaches.'},
    {q:'What does the CDPA protect in relation to software',opts:['Software patents covering the ideas behind the code','Software copyright treating programs as literary works protected from copying without licence','Software trademarks covering names and logos'],ok:1,hint:'CDPA 1988 means copying software without a licence infringes copyright. Commercial piracy can involve criminal liability.'},
    {q:'What is an acceptable use policy',opts:['A policy restricting internet speed for personal use','A policy defining what employees may and may not do with company IT systems','A list of approved software licences'],ok:1,hint:'Violating an AUP is typically an internal disciplinary matter unless it also breaches criminal law such as the CMA.'},
    {q:'What is informed consent in data collection',opts:['Telling users about collection in the small print','Users actively agreeing after being clearly informed what their data will be used for','Staff being trained on data handling'],ok:1,hint:'Consent must be freely given, specific, informed and unambiguous. Pre-ticked boxes do not constitute valid consent.'},
    {q:'What does DPA Principle 7 require',opts:['Data must be kept accurate and up to date','Appropriate technical and organisational security measures must protect personal data','Data must only be used for its original purpose'],ok:1,hint:'Principle 7 is directly relevant to cybersecurity. Organisations suffering breaches due to inadequate security may face ICO enforcement.'},
    {q:'What is a regulatory fine',opts:['A penalty imposed by a criminal court','A financial penalty imposed by a regulator on an organisation that has broken rules','A charge paid to use a regulated service'],ok:1,hint:'ICO fines under DPA 1998 were capped at 500000 pounds. Under GDPR they can reach 20 million euros or 4 percent of global annual turnover.'},
    {q:'CMA Section 2 adds what to Section 1',opts:['The attacker must have caused financial damage','The access must be with intent to commit or facilitate a further criminal offence','The attacker must have modified data'],ok:1,hint:'S2 equals S1 plus further criminal intent. Accessing a system to steal credentials for fraud is S2. Maximum sentence 5 years.'},
    {q:'What is lawful authority for intercepting communications',opts:['Having admin access to an email server','Legal permission such as a court order or statutory authorisation to intercept communications','Being employed by a communications company'],ok:1,hint:'RIPA requires lawful authority. Employers monitoring staff communications need to comply with RIPA and the DPA.'},
    {q:'Copying software without a licence may breach',opts:['CMA 1990','RIPA 2000','CDPA 1988'],ok:2,hint:'CDPA 1988 treats software as a literary work. Copying without a licence is copyright infringement.'},
    {q:'What does data minimisation mean',opts:['Storing data in the smallest possible file format','Collecting only the data necessary for the specified purpose — no more','Deleting all data after each transaction'],ok:1,hint:'Data you do not hold cannot be stolen or misused. Minimisation reduces both privacy risk and breach impact.'}
  ],
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

  generateScenario({numItems=6,difficulty=1}={}){
    const pool = [
      // RED — criminal offences, report to police
      {
        name:'INC-2025-0014', purpose:'Keylogger installed on colleague\'s computer',
        incident:'Employee installed software keylogger on a colleague\'s workstation to capture passwords', legislation:'Computer Misuse Act 1990', section:'Section 3',
        ragAnswer:'R', actionAnswer:'reportPolice',
        notes:'Installing a keylogger without authority constitutes an unauthorised act intended to impair another\'s computer and intercept data — CMA S3 (max 10 years). Report to police. This is not merely a policy issue; it is a criminal offence regardless of whether the perpetrator is an employee.'
      },
      {
        name:'INC-2025-0019', purpose:'Ex-staff remote access after termination',
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
        name:'INC-2025-0031', purpose:'Dev accessed production DB without auth',
        incident:'Developer bypassed access controls and queried the live customer database without approval, claiming they were investigating a performance issue', legislation:'Computer Misuse Act 1990', section:'Section 1',
        ragAnswer:'R', actionAnswer:'reportPolice',
        notes:'Intent does not negate culpability under CMA S1 — the developer accessed a computer system without authorisation. R v Gold & Schifreen (1988) and subsequent CMA cases confirm that "investigating" or "testing" without authority is still unauthorised access. Report to police.'
      },
      {
        name:'INC-2025-0035', purpose:'Staff intercepted manager\'s emails via network tap',
        incident:'Staff member configured a network tap on the manager\'s VLAN segment to capture their email communications', legislation:'Regulation of Investigatory Powers Act 2000', section:'Section 1',
        ragAnswer:'R', actionAnswer:'reportPolice',
        notes:'Unlawful interception of communications — capturing email content in transit — is an offence under RIPA 2000 S1 regardless of the network owner\'s identity. The employee had no lawful authority for interception. Report to police..'
      },
      // AMBER — regulatory breaches, report to ICO / legal
      {
        name:'INC-2025-0008', purpose:'Customer data sold without consent',
        incident:'Marketing manager sold a database of 45,000 customer email addresses to a third-party marketing firm without customer consent', legislation:'Data Protection Act 1998', section:'Principles 1 & 2',
        ragAnswer:'A', actionAnswer:'reportICO',
        notes:'Under DPA 1998, personal data must be processed fairly and lawfully (Principle 1) and only for specified purposes (Principle 2). Selling customer data without consent violates both. Report to the ICO. Customers must be notified. The ICO can issue enforcement notices and, under DPA 1998, fines up to £500,000.'
      },
      {
        name:'INC-2025-0011', purpose:'Payroll data sent to all staff in error',
        incident:'HR administrator sent an email containing all employees\' salaries and NI numbers to the entire company distribution list', legislation:'Data Protection Act 1998', section:'Principle 7',
        ragAnswer:'A', actionAnswer:'reportICO',
        notes:'Accidental disclosure of personal data (salary, NI numbers — "sensitive" under DPA 1998) breaches Principle 7: appropriate security measures must be in place. The ICO must be notified of significant accidental breaches. Affected individuals should be informed. Internal disciplinary action is also appropriate.'
      },
      {
        name:'INC-2025-0026', purpose:'Customer data kept 12 years past contract end',
        incident:'Audit discovered that customer personal data has been retained in the CRM system for 12 years after customers cancelled their accounts — no deletion policy exists', legislation:'Data Protection Act 1998', section:'Principle 5',
        ragAnswer:'A', actionAnswer:'reportICO',
        notes:'DPA 1998 Principle 5: personal data shall not be kept longer than is necessary for the specified purpose. Retaining inactive customer data for 12 years without justification is a clear breach. Report to ICO and implement a data retention and deletion policy immediately.'
      },
      // GREEN — internal policy violations (no criminal/regulatory breach)
      {
        name:'INC-2025-0003', purpose:'Unlicensed software installed on work device',
        incident:'IT audit found that an employee had installed unlicensed copies of design software on their company-issued laptop', legislation:'Copyright Designs & Patents Act 1988', section:'CDPA (internal)',
        ragAnswer:'G', actionAnswer:'internal',
        notes:'Installing unlicensed software violates CDPA 1988 and company IT policy, but this is primarily a licensing/policy issue handled internally. Remove unlicensed software, issue formal warning, purchase appropriate licences. Not a criminal referral in the first instance unless wilful large-scale piracy is involved.'
      },
      {
        name:'INC-2025-0007', purpose:'Analyst accessed own HR record',
        incident:'Junior analyst queried the HR database to view their own salary record and leave balance — access they are not supposed to have but the data was their own', legislation:'Not a breach', section:'Policy only',
        ragAnswer:'G', actionAnswer:'internal',
        notes:'Accessing your own data is not an offence under the CMA (no intent to harm, own data) or DPA (subject access rights exist). The analyst exceeded their system authorisation but the action caused no harm. Address the access control gap and issue a reminder of acceptable use policy. Internal matter only.'
      },
      {
        name:'INC-2025-0016', purpose:'Trainee SQL test on own dev server',
        incident:'Graduate trainee ran SQL injection payloads against the company\'s own development/test environment as a self-directed learning exercise, with no data exfiltration or damage', legislation:'Internal assessment required', section:'Context-dependent',
        ragAnswer:'G', actionAnswer:'internal',
        notes:'Testing on a company-owned test environment the trainee was authorised to use does not constitute unauthorised access (CMA S1 requires no authorisation). No data was at risk. However, this should have been approved in advance. Agree a responsible disclosure / learning process. Internal matter — no criminal referral.'
      },
    ];
    // Adaptive difficulty — set by Analyst Pre-Brief diagnostic score
    var nR,nA,nG;
    if(difficulty===0){           // FOUNDATION: clear-cut cases, minimal edge cases
      nR=pick([2,2,3]); nA=pick([0,0,1]);
    } else if(difficulty===2){    // ADVANCED: edge cases dominate, precision required
      nR=pick([1,1,2]); nA=pick([2,3,3]);
    } else {                      // STANDARD: balanced mix
      nR=pick([1,1,2,2,3]); nA=pick([0,1,1,2]);
    }
    nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Legal, Compliance & HR Department', incorrect:'Network Operations Centre' },
  reportHint: 'Incidents with legal implications need the people who handle law — which team combines legal knowledge with HR?',

  completionText(_,sc){
    const crim=sc.filter(s=>s.ragAnswer==='R').length;
    const reg=sc.filter(s=>s.ragAnswer==='A').length;
    return `<div class="rc info">
      <div style="font-family:'Orbitron',monospace;font-size:11px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:8px;">📁 TECHCORP IR — LEGAL ASSESSMENT</div>
      <p style="margin-bottom:8px;"><strong>${crim} criminal offence(s)</strong> (police notification required), <strong>${reg} regulatory breach(es)</strong> (ICO notification required). ${crim>0?'TechCorp must notify law enforcement immediately — delays in reporting criminal offences create additional legal exposure.':'No criminal offences confirmed in this case set, but the regulatory breaches still carry significant ICO enforcement risk.'}</p>
      <hr style="border-color:rgba(0,255,65,.15);margin:10px 0;">
      <div style="font-family:'Orbitron',monospace;font-size:10px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:6px;">📝 EXAM FOCUS: COMPUTING LEGISLATION</div>
      <p style="font-size:12px;line-height:1.6;">Examiners test <strong>four Acts</strong>: CMA 1990 (S1 unauthorised access 2yr / S2 access with intent 5yr / S3 impairment 10yr), DPA 1998 (8 principles, ICO enforcement), CDPA 1988 (software as literary work), RIPA 2000 (interception). Scenario questions ask you to identify which Act applies — the trick is distinguishing CMA (computer access) from DPA (personal data) from RIPA (communication interception). Know all four Acts cold.</p>
    </div>`;
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
    
      {q:'Under GDPR (which superseded DPA 1998 in 2018), the maximum fine for a serious data breach is:',options:['£500,000 — the maximum under DPA 1998','€20 million or 4% of global annual turnover, whichever is higher','€5 million or 2% of UK turnover, whichever is lower'],correct:1},
      {q:'What is the maximum prison sentence for a Section 3 CMA offence (unauthorised acts with intent to impair)?',options:['2 years — the same as Section 1','5 years — reflecting the additional element of further criminal intent','10 years — reflecting the severity of malware deployment and system impairment'],correct:2},
      {q:'A company discovers its data breach 3 days after it occurred. Under DPA 1998, when should it notify the ICO?',options:['Within 24 hours of the breach occurring','As soon as reasonably practicable after becoming aware — the 72-hour guideline under GDPR is more stringent','Within 28 days — the standard regulatory reporting timeline'],correct:1},
      {q:'Which legislation specifically makes it illegal to intercept email communications in transit without lawful authority?',options:['Computer Misuse Act 1990 — covers all unauthorised access to computer material','Regulation of Investigatory Powers Act 2000 — specifically criminalises the interception of communications in transit','Data Protection Act 1998 — covers the unlawful processing of personal communication data'],correct:1},
      {q:'An employee copies proprietary software from their employer\'s system to a personal USB drive without permission. Which legislation is most directly applicable?',options:['RIPA 2000 — intercepting communications on the company network','DPA 1998 — the software may contain personal data','CMA 1990 Section 1 (unauthorised access to computer material) and potentially CDPA 1988 (copyright in software as literary work)'],correct:2},
      {q:'What is the key legal distinction between CMA Section 1 and Section 2?',options:['Section 1 applies to external attackers; Section 2 applies to employees','Section 1 requires only that access was unauthorised; Section 2 additionally requires intent to commit or facilitate a further criminal offence','Section 1 covers computer access; Section 2 covers interception of communications'],correct:1},
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
    return 'Analyst,\n\nTechCorp\'s help desk logged several unusual contact attempts '
      +'in the days before the breach. We now believe the attacker used social engineering '
      +'to gather intelligence and access credentials before the technical phase of the attack began.\n\n'
      +'Identifying which contacts were part of the attack chain is critical — '
      +'it will determine whether staff disciplinary action is needed, '
      +'and whether we need to notify specific employees about potential credential compromise.\n\n'
      +'Load the Social Engineering Alert Triage tool.\n\n'
      +'Threat Intelligence — TechCorp IR';
  },
  diagnosticSummary:'Social engineering exploits human psychology. Attack types: phishing (deceptive email), spear-phishing (targeted personalised), vishing (phone), smishing (SMS), pretexting (fabricated scenario), baiting (physical or digital lure), tailgating (physical access), BEC (executive impersonation). Psychological levers: urgency, authority, scarcity, social proof. Universal defence: verify through a separate pre-established channel.',
  diagnosticQuestions:[
    {q:'What is social engineering in security',opts:['Designing systems easy for humans to use','Manipulating people into revealing information or taking actions that compromise security','Hacking into social media platforms'],ok:1,hint:'Social engineering targets humans rather than systems. One deceived employee can defeat perfect technical controls entirely.'},
    {q:'What is phishing',opts:['A technique for testing network security','An attack using deceptive emails or websites to trick users into revealing credentials or installing malware','Software that monitors employee internet use'],ok:1,hint:'Phishing is the most common cyberattack vector — cheap, scalable and exploits human trust rather than technical vulnerabilities.'},
    {q:'What is two-factor authentication',opts:['Requiring two administrators to approve each login','Using two separate verification methods to confirm identity','Logging in with two passwords'],ok:1,hint:'2FA means stolen passwords alone are useless. The attacker also needs the second factor which is typically a physical device.'},
    {q:'What is vishing',opts:['A visual security inspection','A phishing attack conducted over the phone','Malware that records video from a device camera'],ok:1,hint:'The 2020 Twitter hack was accomplished primarily through vishing. Attackers called employees impersonating IT support.'},
    {q:'What makes spear-phishing more effective than generic phishing',opts:['It uses physical mail instead of email','It is personalised with researched details such as real names job titles and project references making it appear highly credible','It only targets government organisations'],ok:1,hint:'Generic phishing sends millions of identical emails. Spear-phishing sends one carefully crafted message to one carefully researched target.'},
    {q:'Why is urgency effective as a manipulation technique',opts:['Urgent requests receive legal priority','Urgency creates time pressure that overrides careful critical thinking and the instinct to verify','IT systems automatically prioritise urgent requests'],ok:1,hint:'Urgency is the attacker primary weapon — specifically designed to prevent the victim from pausing to check or verify.'},
    {q:'What is pretexting',opts:['A backup plan when the main attack fails','A fabricated plausible scenario used to establish trust before making a request','A scenario used in security awareness training'],ok:1,hint:'Pretexting is an invented backstory to give the attacker credibility before requesting access or information.'},
    {q:'What is baiting in social engineering',opts:['Enticing employees with bonuses to report incidents','Using physical media or digital lures to exploit human curiosity such as a USB drive labelled Payroll','Sending fake job offers to extract information'],ok:1,hint:'Baiting exploits curiosity. Studies show most found USB drives are plugged in within minutes.'},
    {q:'What is tailgating in physical security',opts:['Following employees on social media','Gaining unauthorised physical access by following an authorised person through a secured door','Monitoring vehicles near a secure facility'],ok:1,hint:'Tailgating exploits politeness — people hold doors open. Turnstiles and a culture of challenging unfamiliar faces are the defences.'},
    {q:'What is BEC (Business Email Compromise)',opts:['A bug in business email software','Fraud where attackers impersonate executives to pressure employees into making unauthorised transfers','Blocking business email to extort payment'],ok:1,hint:'BEC is responsible for billions in annual losses. Finance teams are the primary target. Dual authorisation and verbal confirmation are the fix.'},
    {q:'Why should you never share a password with IT support',opts:['IT staff are not trusted with sensitive data','Legitimate IT staff never need your password because they have administrative access through other means','Passwords are encrypted and IT cannot read them'],ok:1,hint:'Any request for your password is either unnecessary if from legitimate IT or malicious if from an attacker.'},
    {q:'What is a lookalike domain',opts:['A domain that resolves to two different IP addresses','A fraudulent domain designed to appear similar to a legitimate one — for example paypa1.com instead of paypal.com','A domain registered in another country'],ok:1,hint:'Lookalike domains are used in phishing and BEC. Differences are subtle: replacing l with 1, adding a hyphen, or swapping the TLD.'},
    {q:'What is smishing',opts:['A social media phishing attack','A phishing attack delivered via SMS text messages','A physical access attack using a friendly approach'],ok:1,hint:'Smishing uses SMS because people trust text messages more than email. Common: fake delivery notifications and bank fraud alerts.'},
    {q:'What is social proof as a manipulation technique',opts:['Evidence gathered from social media about a target','Implying that others have already complied to encourage the target to do the same','Verifying identity through social media profiles'],ok:1,hint:'Everyone else has already done this. This exploits the human tendency to follow what others appear to be doing.'},
    {q:'The best defence against social engineering is',opts:['Advanced antivirus software on all endpoints','Security awareness training combined with clear verification procedures for unusual requests','Blocking all external phone calls'],ok:1,hint:'Technical controls cannot defend against human manipulation. Awareness training and a verify-before-you-comply culture are the only effective defences.'},
    {q:'What is multi-factor authentication',opts:['Requiring multiple users to approve each action','Using two or more verification factors — something you know have or are — to confirm identity','Changing your password multiple times per month'],ok:1,hint:'MFA defeats credential theft. Even if a password is stolen the attacker also needs the second factor.'},
    {q:'What is CEO fraud',opts:['An executive accidentally deleting critical data','Attackers impersonating executives to pressure finance staff into making unauthorised payments','A CEO committing insider trading using company systems'],ok:1,hint:'CEO fraud exploits authority bias. The fix is dual authorisation and verbal confirmation on a known number.'},
    {q:'Why must you verify through a separate channel',opts:['Because the original channel may be monitored','Because the attacker may have compromised or be impersonating the original channel so a separate channel breaks the deception','Because it creates an audit trail'],ok:1,hint:'If an attacker is impersonating your colleague by email asking them to verify by email is useless. Call on a number from the company directory.'},
    {q:'What does authority mean as a social engineering lever',opts:['The legal right to demand compliance','Exploiting the tendency to comply with perceived authority figures such as managers IT staff or auditors','Demonstrating technical expertise to gain trust'],ok:1,hint:'Authority is highly effective because people are conditioned to follow instructions from authority figures.'},
    {q:'What did the 2020 Twitter hack demonstrate',opts:['That Twitter encryption was broken','That social engineering alone without any technical exploit can compromise major organisations by targeting internal staff','That two-factor authentication is ineffective'],ok:1,hint:'Attackers called Twitter employees posing as IT support, obtained VPN credentials and accessed internal tools. No technical vulnerability was exploited.'}
  ],
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

  generateScenario({numItems=6,difficulty=1}={}){
    const pool = [
      // RED — clear social engineering attacks
      {
        name:'SE-001', purpose:'Phone call to IT help desk claiming urgent account issue',
        channel:'Phone', claimedIdentity:'IT caller — claims senior manager', asks:'Password reset + MFA disabled', redflag:'Urgency, MFA bypass, voice-only', request:'Caller asks IT to reset password and disable MFA — claims locked out before board meeting',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Classic vishing attack. Legitimate users reset passwords through self-service portals with identity verification. Requests to disable MFA over the phone are never legitimate. The claimed urgency (board meeting) is a pressure tactic. Block and report.'
      },
      {
        name:'SE-002', purpose:'Email asking for emergency bank transfer',
        channel:'Email', claimedIdentity:'CEO (lookalike domain: ceo-company.net)', asks:'Transfer £18,500 to new supplier urgently', redflag:'Lookalike domain, secrecy, urgency', request:'Asks Finance to transfer £18,500 — urgently and confidentially, before the board sees it',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Business Email Compromise (CEO fraud). The domain is a lookalike — ceo-company.net vs company.com. The combination of financial request, urgency and secrecy ("before the board sees it") are the classic BEC triad. Verify all bank transfer requests by calling the requestor directly on a known number.'
      },
      {
        name:'SE-003', purpose:'Spear-phishing email referencing real internal project',
        channel:'Email', claimedIdentity:'IT Security (company-support.co.uk)', asks:'Click link to re-authenticate to SharePoint', redflag:'External domain, project name used as lure', request:'References Project Meridian by name, requests re-authentication via link to new SharePoint',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Spear-phishing: the attacker has researched the company and used a real project name to build credibility. The sender domain (company-support.co.uk) is not the company\'s actual domain. The link leads to a credential-harvesting page. The personalisation is the attack — it makes it feel legitimate.'
      },
      {
        name:'SE-004', purpose:'USB drive left in company car park',
        channel:'Physical', claimedIdentity:'Unknown (labelled Salary Review USB)', asks:'(None — employee plugged it in)', redflag:'Physical media, curiosity/self-interest lure', request:'Multiple drives found in car park. Employee plugged one in to identify the owner.',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Baiting attack: the label exploits curiosity and self-interest. Once plugged in, the drive executes a payload automatically or prompts the user to enable macros. Isolate the affected workstation immediately. Never plug unknown media into a work device — the "I just wanted to return it" instinct is the attack vector.'
      },
      {
        name:'SE-005', purpose:'Contractor requesting server room access without prior arrangement',
        channel:'Physical', claimedIdentity:'Halon Systems Ltd contractor (unbooked)', asks:'Server room access for fire inspection', redflag:'No appointment, unescorted, unverified', request:'Unannounced arrival, requests server room access for fire safety inspection, shows business card',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Pretexting with physical tailgating attempt. The scenario creates a plausible cover (fire safety) but no appointment exists and no company badge verification is possible. Legitimate contractors are always pre-booked, escorted and signed in. Deny access, ask them to rebook through Facilities.'
      },
      {
        name:'SE-006', purpose:'LinkedIn message requesting internal technical details',
        channel:'Social Media', claimedIdentity:'Competitor recruiter (profile: 2 weeks old)', asks:'Share infrastructure technical details', redflag:'New account, unsolicited, intel gathering', request:'Asks about technical pain points with current infrastructure, offers referral bonus for information',
        ragAnswer:'R', actionAnswer:'block',
        notes:'Competitive intelligence gathering / corporate espionage. The new account, unsolicited contact and requests for internal technical detail are the indicators. This is social engineering even without a technical payload — sharing internal infrastructure details aids targeted attacks.'
      },
      // AMBER — suspicious, verify before proceeding
      {
        name:'SE-007', purpose:'Email from "Microsoft" about Azure account suspension',
        channel:'Email', claimedIdentity:'Microsoft Azure (microsoft-cloud-support.com)', asks:'Login via link to update billing details', redflag:'Suspicious domain — not microsoft.com', request:'Azure subscription suspended in 48h due to billing issue — requests login to update payment',
        ragAnswer:'A', actionAnswer:'verify',
        notes:'The sender domain is suspicious (microsoft-cloud-support.com, not microsoft.com) but the message content is plausible. The company does use Azure. Verify directly by logging into portal.azure.com — never via the link in this email. Could be phishing or could be a legitimate notification routed through a third-party billing service.'
      },
      {
        name:'SE-008', purpose:'Help desk ticket asking to whitelist a new software tool',
        channel:'Internal ticketing system', claimedIdentity:'Development team lead (ticketing system)', asks:'Whitelist new open-source analysis tool', redflag:'Verify: external tool needs security review', request:'Via official ticketing system: whitelist a new open-source dependency analysis tool',
        ragAnswer:'A', actionAnswer:'verify',
        notes:'Submitted through the correct channel (internal ticketing), which reduces risk. However, whitelisting external tools creates a potential supply chain risk. Verify the request is genuine with the development manager, and check whether the tool has been security-reviewed. Not a clear attack but verification is warranted.'
      },
      {
        name:'SE-009', purpose:'SMS claiming to be from company IT about an urgent system alert',
        channel:'SMS', claimedIdentity:'IT Support (unknown SMS number)', asks:'Reply YES or call to freeze account', redflag:'SMS channel, unknown number, urgency', request:'URGENT: Your work account has been compromised. Reply YES to freeze it or call 0800 XXX XXXX',
        ragAnswer:'A', actionAnswer:'verify',
        notes:'Smishing (SMS phishing). Company IT does not send account alerts via personal SMS or use freephone numbers for security issues. However, an actual breach notification would also be unusual. Do not reply or call the number — contact IT support through the official internal number instead.'
      },
      // GREEN — legitimate, no action needed
      {
        name:'SE-010', purpose:'Password reset email from company IT portal',
        channel:'Email', claimedIdentity:'IT Help Desk (helpdesk@company.com)', asks:'Reset via internal portal (intranet link)', redflag:'None — company domain, internal portal', request:'Standard password expiry notification linking to internal self-service portal (intranet.company.com)',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: correct internal domain, links to the company intranet (not an external site), standard process, no urgency or unusual request. Password expiry notifications from the internal domain with internal portal links are expected. No social engineering indicators.'
      },
      {
        name:'SE-011', purpose:'Procurement: new supplier onboarding form',
        channel:'Email via official procurement system', claimedIdentity:'Procurement (procurement@company.com)', asks:'Complete supplier due diligence forms', redflag:'None — official system, reference number', request:'Automated procurement system notification: complete standard supplier due diligence forms',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate business process. Sent from the correct internal domain via the official procurement system with a reference number. No requests for credentials or out-of-process payments. This is normal supplier onboarding.'
      },
      {
        name:'SE-012', purpose:'Fire safety inspection — pre-booked visit',
        channel:'Email confirmation + Reception log', claimedIdentity:'Facilities Management + verified contractor', asks:'Annual fire system inspection access', redflag:'None — pre-booked, ID verified, escorted', request:'Pre-booked annual fire inspection, confirmed 3 weeks ago, contractor verified with photo ID and escorted',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: appointment pre-booked in advance, contractor verified with photo ID, escorted throughout. This is precisely the process that SE-005 (the pretexting attack) was trying to bypass. The contrast is the point — process compliance is the defence.'
      },
    ];
    // Adaptive difficulty — set by Analyst Pre-Brief diagnostic score
    var nR,nA,nG;
    if(difficulty===0){           // FOUNDATION: clear-cut cases, minimal edge cases
      nR=pick([2,2,3]); nA=pick([0,0,1]);
    } else if(difficulty===2){    // ADVANCED: edge cases dominate, precision required
      nR=pick([1,1,2]); nA=pick([2,3,3]);
    } else {                      // STANDARD: balanced mix
      nR=pick([1,1,2,2,3]); nA=pick([0,1,1,2]);
    }
    nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Security Awareness & HR Department', incorrect:'Network Operations Centre' },
  reportHint: 'Social engineering attacks exploit people — which team handles human-factor security and staff incidents?',

  completionText(_,sc){
    const att=sc.filter(s=>s.ragAnswer!=='G').length;
    return `<div class="rc info">
      <div style="font-family:'Orbitron',monospace;font-size:11px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:8px;">📁 TECHCORP IR — SOCIAL ENGINEERING ANALYSIS</div>
      <p style="margin-bottom:8px;"><strong>${att} suspicious contact(s)</strong> identified in the pre-breach window. ${att>0?'This confirms the attacker ran a social engineering phase before the technical attack — gathering credentials, access, and internal knowledge that made the later technical exploitation much easier.':'The suspicious contacts appear to be unrelated to the breach, but demonstrate the kind of targeting TechCorp faces.'}</p>
      <hr style="border-color:rgba(0,255,65,.15);margin:10px 0;">
      <div style="font-family:'Orbitron',monospace;font-size:10px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:6px;">📝 EXAM FOCUS: SOCIAL ENGINEERING & NETWORK THREATS</div>
      <p style="font-size:12px;line-height:1.6;">Examiners expect you to: <strong>name and distinguish attack types</strong> (phishing/spear-phishing/vishing/smishing/pretexting/baiting/BEC), <strong>identify psychological techniques</strong> (urgency, authority, scarcity, reciprocity), <strong>explain defences</strong> (security awareness training, verification procedures). A common 2-mark question: "Give two features of a spear-phishing email that make it more effective than generic phishing." Answer: personalised to target (1 mark) using researched details such as real colleague names or project references (1 mark).</p>
    </div>`;
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
    
      {q:'What is smishing?',options:['A form of phishing that uses social media messages to deliver malicious links','A phishing attack delivered via SMS text messages','A physical tailgating attack where the attacker "smiles" their way past security'],correct:1},
      {q:'Why does spear-phishing succeed more often than generic phishing?',options:['Spear-phishing emails always contain malware attachments; generic phishing relies only on links','Spear-phishing is personalised using researched details (real names, project references, job titles), making it appear more credible and reducing the victim\'s suspicion','Spear-phishing exploits software vulnerabilities; generic phishing relies on social manipulation alone'],correct:1},
      {q:'What psychological principle does "Your account will be permanently deleted in 24 hours" primarily exploit?',options:['Reciprocity — the victim feels they owe the company compliance','Urgency and scarcity — creating time pressure that overrides careful, critical thinking','Social proof — implying most users have already verified their accounts'],correct:1},
      {q:'An attacker calls a receptionist pretending to be from the fire safety inspection company and requests immediate server room access. What type of attack is this?',options:['Vishing — the attack uses a voice call to obtain information or access','Pretexting — a fabricated but plausible scenario designed to gain trust and physical access','Baiting — using the promise of something desirable to lure the victim'],correct:1},
      {q:'What is tailgating in physical security?',options:['Following a legitimate employee through a secure door without using your own credentials','Reading over someone\'s shoulder to obtain their password or PIN','Installing tracking software on a victim\'s device to monitor their location'],correct:0},
      {q:'Which of the following represents the most complete defence against social engineering?',options:['Installing next-generation antivirus software on all employee workstations','Blocking all external phone calls to prevent vishing','Security awareness training combined with clear verification procedures — all unusual requests confirmed through a separate, pre-established channel'],correct:2},
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
    return 'Analyst,\n\nPost-breach, TechCorp\'s EDR is flagging unusual process behaviour '
      +'across multiple workstations. The attacker may still have persistent access.\n\n'
      +'TIME-CRITICAL: if ransomware deploys while we\'re investigating, '
      +'TechCorp\'s payment processing stops entirely — 500,000 customers affected, '
      +'potential losses in the tens of thousands per hour.\n\n'
      +'Any confirmed malware means immediate host isolation. '
      +'Load the Endpoint Detection Log Viewer and work fast.\n\n'
      +'Incident Response Lead — TechCorp IR';
  },
  diagnosticSummary:'Malware types: virus attaches to files and needs user action to spread. Worm self-replicates across networks without user action. Trojan is disguised as legitimate software. Ransomware encrypts files and demands payment. Keylogger captures keystrokes. Spyware exfiltrates data silently. Rootkit hides other malware. Indicators of Compromise include suspicious process paths, unexpected network connections and abnormal CPU or disk activity.',
  diagnosticQuestions:[
    {q:'What is malware',opts:['Poorly written software that causes crashes','Software designed to disrupt damage or gain unauthorised access to a computer system','A tool used by security professionals to test systems'],ok:1,hint:'Malware covers viruses, worms, trojans, ransomware, spyware, keyloggers, rootkits and botnets.'},
    {q:'What distinguishes a worm from a virus',opts:['A worm encrypts files a virus does not','A worm self-replicates across a network without needing a host file or user action while a virus requires user execution to spread','A worm only affects email servers'],ok:1,hint:'WannaCry spread so rapidly because it used worm functionality via EternalBlue. No user had to click anything — it propagated automatically.'},
    {q:'What is a trojan horse in computing',opts:['An ancient technique for bypassing physical security','Malware disguised as legitimate software to trick users into installing it','A virus targeting only legacy systems'],ok:1,hint:'Trojans exploit trust. They rely on the user installing them willingly believing them to be something useful.'},
    {q:'What is ransomware',opts:['Software that locks a screen until a puzzle is solved','Malware that encrypts files and demands payment for the decryption key','Adware that hijacks browser searches'],ok:1,hint:'Ransomware can encrypt every file on every connected system. WannaCry hit the NHS in 2017 cancelling thousands of appointments.'},
    {q:'What is a keylogger',opts:['Software that monitors login attempts','Malware that records keystrokes to capture passwords and sensitive data','Hardware that tests keyboard functionality'],ok:1,hint:'Keyloggers capture everything typed including passwords and credit card numbers. The data is typically sent to the attacker via a C2 channel.'},
    {q:'What does an EDR system do',opts:['Encrypts data on endpoint devices','Monitors endpoint behaviour for suspicious activity and enables rapid investigation and response','Manages hardware inventory on endpoints'],ok:1,hint:'EDR provides complete visibility into endpoint activity — processes, network connections, file changes. It lets analysts replay exactly what malware did.'},
    {q:'What is a rootkit',opts:['Software that grants root-level admin access','Malware designed to hide the presence of other malware by modifying the operating system','Software that scans for root certificates'],ok:1,hint:'Rootkits subvert the OS itself. Standard tools like Task Manager may show a clean system while malware runs invisibly beneath it.'},
    {q:'What is a botnet',opts:['A network of security cameras','A network of compromised computers controlled remotely to perform coordinated attacks','A test environment for security researchers'],ok:1,hint:'Botnets are used for DDoS attacks, spam, credential stuffing and cryptomining. Infected machines appear normal to their owners.'},
    {q:'What is a C2 (command and control) server',opts:['The primary server managing company databases','A server attackers use to send instructions to and receive data from compromised machines','A failover server that activates if the primary fails'],ok:1,hint:'C2 channels allow attackers to control malware remotely. Periodic check-in connections at fixed intervals are a key indicator.'},
    {q:'What is persistence in malware terms',opts:['Malware that is difficult to detect','The ability of malware to survive a reboot by modifying startup mechanisms such as registry keys and scheduled tasks','The speed at which malware replicates'],ok:1,hint:'Persistent malware ensures continued access after a reboot. Thorough incident response must find and remove all persistence mechanisms.'},
    {q:'What is spyware',opts:['Software used by security teams to monitor networks','Malware that covertly collects information and sends it to an attacker','Government surveillance software installed with legal authority'],ok:1,hint:'Spyware operates silently exfiltrating data over time. Victims may not notice for months.'},
    {q:'What is lateral movement in an intrusion',opts:['Spreading malware to other countries','Moving from the initially compromised machine to other systems within the same network to reach higher-value targets','Redirecting traffic to conceal the attack source'],ok:1,hint:'Lateral movement is how attackers go from a workstation foothold to a domain controller. It often uses legitimate admin tools.'},
    {q:'Why is a process in AppData Temp suspicious',opts:['AppData is a protected folder users cannot access','Legitimate Windows system processes run from System32 not user-writable directories like AppData Temp','Temp folders are deleted automatically making processes there unstable'],ok:1,hint:'Malware uses writable locations because it does not need admin rights there. System processes have no reason to run from user-writable directories.'},
    {q:'What is a zero-day vulnerability',opts:['A vulnerability known for less than 24 hours','A vulnerability unknown to the software vendor with no available patch','A vulnerability only affecting newly installed software'],ok:1,hint:'Zero-day means the vendor has had zero days to fix it. Zero-days are extremely valuable to attackers since they cannot be patched until discovered.'},
    {q:'What is cryptojacking',opts:['Stealing and ransoming encrypted files','Using a victim computer without consent to mine cryptocurrency causing high CPU usage and elevated electricity costs','Intercepting and decrypting HTTPS traffic'],ok:1,hint:'Cryptojacking is low-profile but costly. Victims notice sluggish performance and higher electricity bills.'},
    {q:'What is an Indicator of Compromise',opts:['A certificate proving a system is secure','Forensic evidence suggesting a system has been breached such as a suspicious process unexpected network connection or new scheduled task','A risk score assigned to a known vulnerability'],ok:1,hint:'IoCs are what analysts hunt for: unusual process names, unexpected outbound connections, modified system files and accounts the IT team did not create.'},
    {q:'What does isolating a compromised host mean',opts:['Physically removing the hard drive','Disconnecting the device from the network to prevent further spread while preserving forensic evidence','Immediately deleting all files on the machine'],ok:1,hint:'Isolation stops spread and cuts the C2 channel while preserving evidence. It is typically the first response to confirmed malware.'},
    {q:'What is a backdoor',opts:['An undocumented developer access mechanism','Hidden persistent remote access installed by malware giving the attacker ongoing entry independent of the initial intrusion','A secondary administrator account'],ok:1,hint:'Even after cleaning a system an undiscovered backdoor gives the attacker a way back in. All persistence mechanisms must be found and removed.'},
    {q:'What is an antivirus signature',opts:['A certificate proving antivirus is genuine','A pattern or fingerprint used to identify a specific piece of known malware','An approval stamp from a security audit'],ok:1,hint:'Signature-based detection is fast for known malware but fails against new or modified threats. Behavioural detection fills this gap.'},
    {q:'How does a virus differ from a worm in spreading',opts:['Viruses spread via network worms spread via email','A virus requires a host file and user action to spread while a worm is self-contained and self-propagating requiring no user interaction','A virus is always destructive a worm is always passive'],ok:1,hint:'This distinction is a common exam question. Viruses need user execution. Worms exploit network services and spread automatically.'}
  ],
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

  generateScenario({numItems=6,difficulty=1}={}){
    const pool = [
      // RED — confirmed malware behaviour
      {
        name:'svchost_fake.exe', purpose:'Masquerading as Windows system process',
        path:'C:\\Users\\jsmith\\AppData\\Temp\\svchost_fake.exe', location:'AppData\\Temp\\ ⚠', activity:'8,000 writes/min, .encrypted extension', connections:'→ 91.108.4.201:443 (non-Microsoft IP)',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Ransomware. Legitimate svchost.exe runs only from C:\\Windows\\System32 — a copy in AppData\\Temp is an immediate red flag (process name spoofing). The high file write rate with new extensions and outbound connection to an external IP (likely C2 server receiving the encryption key) are definitive. Isolate immediately.'
      },
      {
        name:'keylog32.exe', purpose:'Hidden process with keyboard and clipboard access',
        path:'C:\\ProgramData\\WindowsHelper\\keylog32.exe', location:'ProgramData (non-standard dir)', activity:'Keyboard API hook + clipboard capture', connections:'→ 45.92.14.99:80 (3-min C2 interval)',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Keylogger. SetWindowsHookEx is the Windows API used to intercept all keyboard input. Writing captured data to a hidden file and exfiltrating it via periodic outbound connections is the classic keylogger pattern. The regular interval suggests automated exfiltration. Isolate and preserve the log file as evidence.'
      },
      {
        name:'update_helper.exe', purpose:'Process spreading to network shares',
        path:'C:\\Windows\\Temp\\update_helper.exe', location:'Windows\\Temp\\ ⚠', activity:'Self-copying to network shares + autorun.inf', connections:'SMB:445 → 47 internal hosts / 10 min',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Worm. Self-replication to network shares via SMB (port 445) without user interaction is the defining worm behaviour. Autorun.inf files execute the payload automatically when a drive is accessed. The breadth of lateral spread (47 hosts in 10 minutes) indicates it is already propagating. Isolate the source host immediately and check all connected shares.'
      },
      {
        name:'pdf_viewer_pro.exe', purpose:'Trojan with remote access capability',
        path:'C:\\Users\\mwilson\\Downloads\\pdf_viewer_pro.exe', location:'User Downloads\\ ⚠', activity:'PDF UI front + reverse shell opened', connections:'Persistent → 203.0.113.42:4444 (C2)',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Trojan horse with remote access (RAT). Port 4444 is a well-known default for Metasploit reverse shells. The process presents as a legitimate PDF viewer (the trojan component) while maintaining a persistent connection to an attacker-controlled server. The user likely downloaded it believing it was genuine software.'
      },
      {
        name:'sysmon_helper.exe', purpose:'Spyware capturing screen and exfiltrating data',
        path:'C:\\ProgramData\\Monitoring\\sysmon_helper.exe', location:'ProgramData (non-standard dir)', activity:'Screenshots + browser creds + .zip upload', connections:'→ unauthorised cloud storage API',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Spyware. Unlike a keylogger (keyboard only), this captures broader intelligence: screenshots, browser history and saved credentials. Exfiltration to unauthorised cloud storage is a data loss indicator. The name (sysmon_helper) mimics the legitimate Sysinternals Sysmon tool — another name spoofing attempt.'
      },
      {
        name:'powershell.exe', purpose:'Encoded PowerShell execution at 03:14',
        path:'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', location:'System32 (legit path — check flags)', activity:'-ExecutionPolicy Bypass -Hidden at 03:14', connections:'→ 104.21.77.33 during execution only',
        ragAnswer:'R', actionAnswer:'isolate',
        notes:'Malicious PowerShell execution. -ExecutionPolicy Bypass overrides the policy preventing unsigned scripts. -WindowStyle Hidden prevents the user seeing the window. -EncodedCommand is base64-encoded to evade signature detection. Scheduled task at 03:14 minimises visibility. Legitimate scripts do not require these flags. Decode the base64 and investigate.'
      },
      // AMBER — suspicious, requires investigation
      {
        name:'chrome.exe (unusual)', purpose:'Browser process making high-volume API calls',
        path:'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', location:'Program Files (Google) ✓', activity:'2,000 ad API requests/hr — 10× normal', connections:'→ multiple ad-network domains',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:'Suspicious but not confirmed malware. The path is legitimate (correct Chrome installation directory). However, the request rate is abnormal — could indicate a malicious browser extension performing ad fraud or cryptojacking. Investigate installed extensions and check for recent installs. The process itself is genuine; the behaviour warrants investigation.'
      },
      {
        name:'wscript.exe', purpose:'Windows Script Host executing VBScript',
        path:'C:\\Windows\\System32\\wscript.exe', location:'System32 ✓ (check what it runs)', activity:'.vbs from Downloads + registry reads', connections:'→ script-delivery.net:80 ⚠',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:'Suspicious script execution. wscript.exe itself is a legitimate Windows tool, but executing a script from Downloads that accesses the registry and makes network connections is a common malware delivery technique. The domain (script-delivery.net) is not a recognised business destination. Investigate the .vbs file contents.'
      },
      {
        name:'msiexec.exe (silent)', purpose:'Silent MSI package installation',
        path:'C:\\Windows\\System32\\msiexec.exe', location:'System32 ✓ (check install source)', activity:'/quiet /norestart — installing to ProgramData', connections:'Installer from 185.220.101.28 ⚠',
        ragAnswer:'A', actionAnswer:'investigate',
        notes:'Potentially unwanted installation. msiexec.exe is the legitimate Windows Installer, but /quiet suppresses the UI and the source IP is not a known software vendor. This could be a legitimate admin deployment or a malicious installer. Verify with the IT team whether this installation was authorised.'
      },
      // GREEN — legitimate system activity
      {
        name:'MsMpEng.exe', purpose:'Windows Defender antivirus scan',
        path:'C:\\ProgramData\\Microsoft\\Windows Defender\\...\\MsMpEng.exe', location:'Windows Defender (known path) ✓', activity:'Full disk scan — high CPU (scheduled)', connections:'→ Microsoft threat intel feeds ✓',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: MsMpEng.exe is the Windows Defender antimalware engine. High CPU during a full scan is expected. The path is a known legitimate location. Connections to Microsoft threat intelligence endpoints are standard behaviour. No action required.'
      },
      {
        name:'wuauclt.exe', purpose:'Windows Update downloading patches',
        path:'C:\\Windows\\System32\\wuauclt.exe', location:'System32 ✓', activity:'Downloading patches → SoftwareDistribution', connections:'→ windowsupdate.microsoft.com ✓',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: wuauclt.exe is the Windows Update agent. Downloading from verified Microsoft CDN addresses and writing to the standard Windows Update cache directory is expected patch management behaviour. Allow.'
      },
      {
        name:'VeeamAgent.exe', purpose:'Backup software reading all files',
        path:'C:\\Program Files\\Veeam\\Endpoint Backup\\VeeamAgent.exe', location:'Program Files (Veeam) ✓', activity:'4,200 reads/min — scheduled backup', connections:'→ NAS 192.168.10.50 (internal) ✓',
        ragAnswer:'G', actionAnswer:'allow',
        notes:'Legitimate: this is the Veeam backup agent performing a scheduled nightly backup. High file read rates during the backup window are expected. The destination is an internal NAS appliance, not an external IP. The path is the correct installed location. Allow.'
      },
    ];
    // Adaptive difficulty — set by Analyst Pre-Brief diagnostic score
    var nR,nA,nG;
    if(difficulty===0){           // FOUNDATION: clear-cut cases, minimal edge cases
      nR=pick([2,2,3]); nA=pick([0,0,1]);
    } else if(difficulty===2){    // ADVANCED: edge cases dominate, precision required
      nR=pick([1,1,2]); nA=pick([2,3,3]);
    } else {                      // STANDARD: balanced mix
      nR=pick([1,1,2,2,3]); nA=pick([0,1,1,2]);
    }
    nG=numItems-nR-nA;
    return _pickPool(pool,nR,nA,Math.max(1,nG));
  },

  reportTeams:{ correct:'Incident Response Team', incorrect:'Facilities Management' },
  reportHint: 'Active malware on endpoints is a live security incident — which team handles containment and forensic response?',

  completionText(_,sc){
    const att=sc.filter(s=>s.ragAnswer==='R').length;
    return `<div class="rc info">
      <div style="font-family:'Orbitron',monospace;font-size:11px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:8px;">📁 TECHCORP IR — ENDPOINT FORENSICS</div>
      <p style="margin-bottom:8px;"><strong>${att} confirmed malware instance(s)</strong> on TechCorp endpoints. ${att>0?'The attacker achieved persistent access — the keylogger confirms credentials were captured, and the trojan maintained a live C2 channel. These hosts must be isolated and imaged immediately before remediation.':'No confirmed malware in this endpoint sample — but the suspicious behaviours warrant further investigation.'}</p>
      <hr style="border-color:rgba(0,255,65,.15);margin:10px 0;">
      <div style="font-family:'Orbitron',monospace;font-size:10px;color:rgba(0,255,65,.5);letter-spacing:.1em;margin-bottom:6px;">📝 EXAM FOCUS: MALWARE & NETWORK THREATS</div>
      <p style="font-size:12px;line-height:1.6;">Examiners test: <strong>malware type definitions</strong> (virus needs user action to spread; worm self-replicates; trojan appears legitimate; ransomware encrypts for payment; keylogger captures input; rootkit hides other malware). <strong>Classic 4-marker</strong>: "Describe how ransomware works and explain one way organisations can protect against it." Top answer: encrypts files making them inaccessible (2) → demands payment for decryption key (1) → defence: offline backups that ransomware cannot reach (1).</p>
    </div>`;
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
    
      {q:'How does a rootkit differ from other malware types?',options:['A rootkit encrypts files and demands payment for decryption — the key difference from ransomware','A rootkit modifies the operating system to hide the presence of other malware — making standard detection tools unreliable on an infected host','A rootkit spreads automatically across a network; other malware types require user interaction'],correct:1},
      {q:'What is cryptojacking?',options:['Stealing encrypted files and ransoming the decryption key','Using a victim\'s computer resources without their knowledge to mine cryptocurrency — causing high CPU usage and electricity costs','Intercepting and decrypting HTTPS traffic by compromising a certificate authority'],correct:1},
      {q:'What is lateral movement in the context of a network intrusion?',options:['The attacker redirecting traffic from one server to another to avoid detection','The attacker moving from the initially compromised machine to other systems on the same network, expanding their access','The attacker using a VPN to make their traffic appear to come from a different geographic location'],correct:1},
      {q:'A backdoor differs from a trojan horse in that:',options:['A backdoor is always installed by the attacker manually; a trojan is always distributed via email','A backdoor specifically provides persistent remote access to a system; a trojan is a broader term for malware disguised as legitimate software (which may include a backdoor)','A backdoor only targets Windows systems; trojans work across all operating systems'],correct:1},
      {q:'What is an Indicator of Compromise (IoC)?',options:['A formal legal notice that a system has been certified as secure','Forensic evidence suggesting a system has been breached — e.g. a suspicious process, unexpected network connection, or new registry key','A risk score assigned to a vulnerability based on its potential impact and exploitability'],correct:1},
      {q:'The WannaCry ransomware spread so rapidly in 2017 because it combined which two capabilities?',options:['Keylogging and screen capture — allowing it to steal credentials from each infected machine before spreading','Worm functionality (self-replication via an SMB vulnerability) and ransomware (encrypting files) — no user action required to propagate','Trojan installation and rootkit concealment — making it invisible to standard antivirus tools'],correct:1},
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
  { key:'name',            label:'CASE ID'      },
  { key:'channel',         label:'CHANNEL'      },
  { key:'claimedIdentity', label:'CLAIMS TO BE' },
  { key:'asks',            label:'REQUESTS'     },
  { key:'redflag',         label:'RED FLAGS'    },
];

MODULE_COLUMNS.malwareAnalysis = [
  { key:'name',        label:'PROCESS'       },
  { key:'location',    label:'PATH TYPE'     },
  { key:'activity',    label:'KEY ACTIVITY'  },
  { key:'connections', label:'NETWORK'       },
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
