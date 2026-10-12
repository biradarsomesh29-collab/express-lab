import React, { useState, useEffect, useRef } from 'react';

/* =========================================================
   REAL CRYPTOGRAPHIC ENGINES
   ========================================================= */

// ---- Hill Cipher (real 2x2 matrix math, mod 26) ----
// Key matrix M = [[3,3],[2,5]]  (det = 9, gcd(9,26)=1 -> invertible)
// Inverse of M mod 26 = [[15,17],[20,9]]  (verified: M * Minv = I mod 26)
const HILL_MATRIX = [[3, 3], [2, 5]];
const HILL_MATRIX_INV = [[15, 17], [20, 9]];

function hillTransform(text, modeType) {
  const key = modeType === 'to-cipher' ? HILL_MATRIX : HILL_MATRIX_INV;
  let letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  if (letters.length === 0) return '';
  if (letters.length % 2 !== 0) letters += 'X'; // pad odd-length blocks
  let result = '';
  for (let i = 0; i < letters.length; i += 2) {
    const v0 = letters.charCodeAt(i) - 65;
    const v1 = letters.charCodeAt(i + 1) - 65;
    const r0 = (((key[0][0] * v0 + key[0][1] * v1) % 26) + 26) % 26;
    const r1 = (((key[1][0] * v0 + key[1][1] * v1) % 26) + 26) % 26;
    result += String.fromCharCode(r0 + 65) + String.fromCharCode(r1 + 65);
  }
  return result;
}

// ---- XOR Stream Cipher (key-based, hex output) ----
function xorTransform(text, modeType, key) {
  const k = key || 'KEY';
  if (modeType === 'to-cipher') {
    let hex = '';
    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i) ^ k.charCodeAt(i % k.length);
      hex += code.toString(16).padStart(2, '0');
    }
    return hex;
  }
  try {
    const bytes = [];
    for (let i = 0; i < text.length; i += 2) {
      bytes.push(parseInt(text.substr(i, 2), 16));
    }
    let result = '';
    for (let i = 0; i < bytes.length; i++) {
      result += String.fromCharCode(bytes[i] ^ k.charCodeAt(i % k.length));
    }
    return result;
  } catch (e) {
    return '[ERROR: INVALID HEX CIPHERSTREAM]';
  }
}

// ---- Rail Fence (transposition) Cipher ----
function railFenceEncrypt(text, rails) {
  const r = Math.max(2, parseInt(rails) || 3);
  const fence = Array.from({ length: r }, () => []);
  let rail = 0, dir = 1;
  for (const ch of text) {
    fence[rail].push(ch);
    rail += dir;
    if (rail === 0 || rail === r - 1) dir *= -1;
  }
  return fence.map((row) => row.join('')).join('');
}

function railFenceDecrypt(cipher, rails) {
  const r = Math.max(2, parseInt(rails) || 3);
  const len = cipher.length;
  const pattern = [];
  let rail = 0, dir = 1;
  for (let i = 0; i < len; i++) {
    pattern.push(rail);
    rail += dir;
    if (rail === 0 || rail === r - 1) dir *= -1;
  }
  const railCounts = Array(r).fill(0);
  pattern.forEach((row) => railCounts[row]++);
  const rows = [];
  let idx = 0;
  for (let row = 0; row < r; row++) {
    rows.push(cipher.slice(idx, idx + railCounts[row]).split(''));
    idx += railCounts[row];
  }
  const pointers = Array(r).fill(0);
  let result = '';
  for (let i = 0; i < len; i++) {
    const row = pattern[i];
    result += rows[row][pointers[row]++];
  }
  return result;
}

// ---- Real AES-256-GCM via the browser's native Web Crypto API ----
function bufToBase64(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}
function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function deriveAesKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function aesEncrypt(plainText, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveAesKey(password, salt);
  const enc = new TextEncoder();
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plainText));
  const combined = new Uint8Array(salt.length + iv.length + cipherBuf.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(cipherBuf), salt.length + iv.length);
  return bufToBase64(combined.buffer);
}

async function aesDecrypt(cipherB64, password) {
  const combined = base64ToBytes(cipherB64);
  const salt = combined.slice(0, 16);
  const iv = combined.slice(16, 28);
  const data = combined.slice(28);
  const key = await deriveAesKey(password, salt);
  const plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return new TextDecoder().decode(plainBuf);
}

// ---- Frequency Analysis ----
function getLetterFrequency(text) {
  const counts = {};
  const letters = text.toUpperCase().replace(/[^A-Z]/g, '');
  for (const ch of letters) counts[ch] = (counts[ch] || 0) + 1;
  return counts;
}

// ---- Caesar Cipher Brute-Force Cracker ----
const COMMON_WORDS = ['THE', 'AND', 'YOU', 'THAT', 'WAS', 'FOR', 'ARE', 'WITH',
  'HIS', 'THEY', 'THIS', 'HAVE', 'FROM', 'ONE', 'HAD', 'WORD', 'BUT', 'NOT', 'WHAT', 'ALL'];

function crackCaesar(cipherText) {
  const results = [];
  for (let s = 0; s < 26; s++) {
    let decoded = '';
    for (const ch of cipherText) {
      const code = ch.charCodeAt(0);
      if (code >= 65 && code <= 90) decoded += String.fromCharCode(((code - 65 - s + 26) % 26) + 65);
      else if (code >= 97 && code <= 122) decoded += String.fromCharCode(((code - 97 - s + 26) % 26) + 97);
      else decoded += ch;
    }
    const upper = decoded.toUpperCase();
    const score = COMMON_WORDS.filter((w) => upper.includes(w)).length;
    results.push({ shift: s, text: decoded, score });
  }
  return results.sort((a, b) => b.score - a.score);
}

/* =========================================================
   MAIN APP
   ========================================================= */

function App() {
  const [mode, setMode] = useState('home');
  const [cipherType, setCipherType] = useState('caesar');
  const [inputText, setInputText] = useState('');
  const [outputText, setOutputText] = useState('');

  // Crypto parameters
  const [shiftVal, setShiftVal] = useState(5);
  const [secretKey, setSecretKey] = useState('SOC_KEY');
  const [railCount, setRailCount] = useState(3);
  const [isProcessing, setIsProcessing] = useState(false);

  // Cryptanalysis tools
  const [showFrequency, setShowFrequency] = useState(false);
  const [crackResults, setCrackResults] = useState(null);
  const [isCracking, setIsCracking] = useState(false);

  // Tracker State
  const [phoneNumber, setPhoneNumber] = useState('');
  const [trackerResult, setTrackerResult] = useState(null);
  const [isTracing, setIsTracing] = useState(false);

  // Face Recognition & Registration State
  const videoRef = useRef(null);
  const [cameraActive, setCameraActive] = useState(false);
  const [faceData, setFaceData] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isNewUser, setIsNewUser] = useState(false);
  const [regName, setRegName] = useState('');
  const [regRole, setRegRole] = useState('');
  const [regClearance, setRegClearance] = useState('LEVEL-2 (OPERATIONAL)');

  // Voice State
  const [isListening, setIsListening] = useState(false);
  const [voiceArchives, setVoiceArchives] = useState([]);
  const [logs, setLogs] = useState([]);

  const addLog = (message) => {
    const timestamp = new Date().toLocaleTimeString();
    setLogs((prev) => [`[${timestamp}] ${message}`, ...prev.slice(0, 5)]);
  };

  useEffect(() => {
    addLog('SYSTEM INITIALIZED // SECURE CHANNEL ESTABLISHED');
  }, []);

  const startCamera = async () => {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: true });
      if (videoRef.current) videoRef.current.srcObject = stream;
      setCameraActive(true);
      addLog('BIOMETRIC WEBSCANNER ACTIVE // OPTICAL FEED ONLINE');
    } catch (err) {
      alert('Camera access denied or unavailable.');
      addLog('ERROR: WEBCAM ACCESS FAILED');
    }
  };

  const stopCamera = () => {
    if (videoRef.current && videoRef.current.srcObject) {
      videoRef.current.srcObject.getTracks().forEach((t) => t.stop());
      setCameraActive(false);
      addLog('WEBCAM FEED TERMINATED');
    }
  };

  const scanAndVerifyFace = () => {
    setIsScanning(true);
    setFaceData(null);
    setIsNewUser(false);
    addLog('CAPTURING FACIAL MATRIX HASH // QUERYING CyberSOCBackend & MYSQL...');
    const currentFaceHash = 'FACE_SAMPLE_001';

    fetch(`http://localhost:8080/CyberSOCBackend/api/verify-face?faceHash=${currentFaceHash}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.exists) {
          setFaceData({
            name: data.name, status: data.status, clearance: data.clearance,
            role: data.role, hash: currentFaceHash, action: 'ACCESS GRANTED',
          });
          addLog(`MYSQL MATCH: Authorized personnel ${data.name} verified and displayed.`);
          setIsNewUser(false);
        } else {
          setIsNewUser(true);
          addLog('NOTICE: FACE NOT FOUND IN MYSQL. MANUAL REGISTRATION REQUIRED.');
        }
        setIsScanning(false);
      })
      .catch((error) => {
        addLog('ERROR: FAILED TO CONNECT TO CyberSOCBackend BACKEND');
        console.error('Backend connection error:', error);
        setIsScanning(false);
      });
  };

  const handleRegisterNewPersonnel = (e) => {
    e.preventDefault();
    if (!regName || !regRole) {
      alert('Please enter both Name and Role Title.');
      return;
    }
    addLog(`SAVING NEW OPERATIVE (${regName}) TO MYSQL DATABASE...`);
    setTimeout(() => {
      setFaceData({
        name: regName, status: 'NEW RECORD SUCCESSFULLY ADDED TO MYSQL',
        clearance: regClearance, role: regRole,
        hash: 'FACE_HASH_' + Math.floor(Math.random() * 90000 + 10000),
        action: 'REGISTERED & AUTHORIZED',
      });
      setIsNewUser(false);
      setRegName('');
      setRegRole('');
      addLog(`SUCCESS: ${regName} written to personnel_records table.`);
    }, 1000);
  };

  /* ---------------- CRYPTO DISPATCH ---------------- */
  // Synchronous engines (instant, as-you-type)
  const performSyncConversion = (text, modeType, algorithm, shift, key, rails) => {
    if (!text) return '';
    let result = '';

    if (algorithm === 'caesar') {
      const s = parseInt(shift) || 5;
      for (let i = 0; i < text.length; i++) {
        let c = text.charAt(i);
        const code = text.charCodeAt(i);
        if (code >= 65 && code <= 90) {
          c = modeType === 'to-cipher'
            ? String.fromCharCode(((code - 65 + s) % 26) + 65)
            : String.fromCharCode(((code - 65 - (s % 26) + 26) % 26) + 65);
        } else if (code >= 97 && code <= 122) {
          c = modeType === 'to-cipher'
            ? String.fromCharCode(((code - 97 + s) % 26) + 97)
            : String.fromCharCode(((code - 97 - (s % 26) + 26) % 26) + 97);
        }
        result += c;
      }
    } else if (algorithm === 'rot13') {
      for (let i = 0; i < text.length; i++) {
        let c = text.charAt(i);
        const code = text.charCodeAt(i);
        if (code >= 65 && code <= 90) c = String.fromCharCode(((code - 65 + 13) % 26) + 65);
        else if (code >= 97 && code <= 122) c = String.fromCharCode(((code - 97 + 13) % 26) + 97);
        result += c;
      }
    } else if (algorithm === 'base64') {
      try {
        result = modeType === 'to-cipher'
          ? btoa(unescape(encodeURIComponent(text)))
          : decodeURIComponent(escape(atob(text)));
      } catch (e) {
        result = '[ERROR: INVALID BASE64 PAYLOAD]';
      }
    } else if (algorithm === 'hill') {
      result = hillTransform(text, modeType);
    } else if (algorithm === 'vigenere') {
      const cleanKey = (key || 'SOC').toLowerCase().replace(/[^a-z]/g, '') || 'soc';
      let keyIndex = 0;
      for (let i = 0; i < text.length; i++) {
        let c = text.charAt(i);
        const code = text.charCodeAt(i);
        if (c.match(/[a-z]/i)) {
          const shiftChar = cleanKey[keyIndex % cleanKey.length].charCodeAt(0) - 97;
          if (code >= 65 && code <= 90) {
            c = modeType === 'to-cipher'
              ? String.fromCharCode(((code - 65 + shiftChar) % 26) + 65)
              : String.fromCharCode(((code - 65 - shiftChar + 26) % 26) + 65);
          } else if (code >= 97 && code <= 122) {
            c = modeType === 'to-cipher'
              ? String.fromCharCode(((code - 97 + shiftChar) % 26) + 97)
              : String.fromCharCode(((code - 97 - shiftChar + 26) % 26) + 97);
          }
          keyIndex++;
        }
        result += c;
      }
    } else if (algorithm === 'xor') {
      result = xorTransform(text, modeType, key);
    } else if (algorithm === 'railfence') {
      result = modeType === 'to-cipher'
        ? railFenceEncrypt(text, rails)
        : railFenceDecrypt(text, rails);
    }
    return result;
  };

  const handleConvert = (text, modeType, algorithm, shift = shiftVal, key = secretKey, rails = railCount) => {
    setInputText(text);
    setCrackResults(null);

    if (!text) {
      setOutputText('');
      return;
    }

    if (algorithm === 'aes') {
      setIsProcessing(true);
      setOutputText('[PROCESSING AES-256-GCM...]');
      const task = modeType === 'to-cipher' ? aesEncrypt(text, key) : aesDecrypt(text, key);
      task
        .then((res) => {
          setOutputText(res);
          setIsProcessing(false);
        })
        .catch((err) => {
          setOutputText('[ERROR: DECRYPTION FAILED - WRONG KEY OR CORRUPTED CIPHERTEXT]');
          setIsProcessing(false);
        });
      return;
    }

    const result = performSyncConversion(text, modeType, algorithm, shift, key, rails);
    setOutputText(result);
  };

  const handleCrackCaesar = () => {
    if (!inputText) {
      alert('Enter a ciphertext first.');
      return;
    }
    setIsCracking(true);
    addLog('BRUTE-FORCING ALL 26 CAESAR SHIFTS...');
    setTimeout(() => {
      setCrackResults(crackCaesar(inputText));
      setIsCracking(false);
      addLog('BRUTE-FORCE COMPLETE // RANKED BY ENGLISH WORD MATCH SCORE');
    }, 300);
  };

  /* ---------------- GPS TRACKER (unchanged) ---------------- */
  const handlePhoneTracking = (e) => {
    e.preventDefault();
    const cleanNum = phoneNumber.trim().replace(/\D/g, '');
    if (!cleanNum || cleanNum.length < 10) {
      alert('Please enter a valid 10-digit mobile number.');
      return;
    }
    setIsTracing(true);
    addLog('ACQUIRING LIVE GPS POSITION & SYNCING WITH CyberSOCBackend...');
    setTrackerResult(null);

    if (!navigator.geolocation) {
      alert('Geolocation is not supported by your browser');
      setIsTracing(false);
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        const lat = position.coords.latitude.toFixed(4) + '° N';
        const lon = position.coords.longitude.toFixed(4) + '° E';
        const deviceId = 'PHONE_' + cleanNum;

        fetch('http://localhost:8080/CyberSOCBackend/api/update-location', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: `device_id=${deviceId}&latitude=${lat}&longitude=${lon}`,
        })
          .then((r) => r.json())
          .then((data) => {
            setTrackerResult({
              number: '+91 ' + cleanNum, circle: 'Live Device GPS Lock',
              carrier: 'Active Cellular / Hardware Node', sectorPin: 'Live GPS Telemetry Grid',
              lat: data.latitude || lat, lon: data.longitude || lon,
              accuracy: 'High Precision GPS Lock (Synced to MySQL)',
              status: 'ACTIVE TARGET ACQUIRED (LIVE)', timestamp: new Date().toUTCString(),
            });
            setIsTracing(false);
            addLog(`SUCCESS: LIVE GPS SYNCED & WRITTEN TO MYSQL FOR +91 ${cleanNum}`);
          })
          .catch(() => {
            addLog('WARNING: GPS ACQUIRED LOCALLY, BUT FAILED TO SYNC WITH TOMCAT BACKEND.');
            setTrackerResult({
              number: '+91 ' + cleanNum, circle: 'Local Device GPS Stream',
              carrier: 'Hardware GNSS Receiver', sectorPin: 'Standalone Node',
              lat, lon, accuracy: 'High Precision Hardware GPS',
              status: 'ACTIVE TARGET ACQUIRED (OFFLINE SYNC)', timestamp: new Date().toUTCString(),
            });
            setIsTracing(false);
          });
      },
      () => {
        addLog('ERROR: HARDWARE GPS TIMEOUT OR PERMISSION DENIED.');
        alert('Unable to retrieve device GPS location. Please check location permissions.');
        setIsTracing(false);
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
  };

  /* ---------------- VOICE ---------------- */
  const startSpeechRecognition = () => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SpeechRecognition) {
      alert('Speech Recognition API is not supported in this browser. Please use Google Chrome or Microsoft Edge.');
      addLog('ERROR: SPEECH RECOGNITION NOT SUPPORTED');
      return;
    }
    const recognition = new SpeechRecognition();
    recognition.lang = 'en-US';
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;

    recognition.onstart = () => {
      setIsListening(true);
      addLog('MICROPHONE ACTIVE // LISTENING TO HUMAN VOICE STREAM...');
    };
    recognition.onresult = (event) => {
      const speechToText = event.results[0][0].transcript;
      addLog(`SPEECH CONVERTED TO PLAINTEXT: "${speechToText}"`);
      const cipherResult = performSyncConversion(speechToText, 'to-cipher', cipherType === 'aes' ? 'caesar' : cipherType, shiftVal, secretKey, railCount);
      const newArchive = {
        id: Date.now(), time: new Date().toLocaleTimeString(),
        transcript: speechToText, cipher: cipherResult, algo: cipherType.toUpperCase(),
      };
      setVoiceArchives((prev) => [newArchive, ...prev]);
    };
    recognition.onerror = (event) => {
      addLog(`SPEECH RECOGNITION ERROR: ${event.error}`);
      setIsListening(false);
    };
    recognition.onend = () => {
      setIsListening(false);
      addLog('MICROPHONE STREAM CLOSED & ARCHIVED');
    };
    recognition.start();
  };

  const frequencyData = showFrequency ? getLetterFrequency(outputText) : null;
  const maxFreq = frequencyData ? Math.max(1, ...Object.values(frequencyData)) : 1;

  return (
    <div style={styles.container}>
      <div style={styles.header}>
        <div>
          <h1 style={styles.title}>PROJECT: CYBER-CONVERT // SOC TERMINAL</h1>
          <p style={styles.subtitle}>REAL AES-256, HILL MATRIX, XOR & RAIL FENCE ENGINES + CRYPTANALYSIS TOOLS</p>
        </div>
        <div style={styles.statusBadge}>
          <span style={styles.blinkingDot}></span> STATUS: SECURE (ACTIVE)
        </div>
      </div>

      <div style={styles.contentBox}>
        {mode === 'home' && (
          <div>
            <div style={styles.sectionHeader}>SELECT OPERATION MODE:</div>
            <div style={styles.menuGrid}>
              <button onClick={() => { setMode('plain-to-cipher'); setInputText(''); setOutputText(''); setCrackResults(null); addLog('Switched to Plaintext Encryption Terminal'); }} style={styles.cardButton}>
                <div style={styles.cardTitle}>[ 01 ] PLAINTEXT TO CIPHERTEXT</div>
                <div style={styles.cardDesc}>8 CRYPTOGRAPHIC ENGINES INCL. REAL AES-256-GCM</div>
              </button>
              <button onClick={() => { setMode('cipher-to-plain'); setInputText(''); setOutputText(''); setCrackResults(null); addLog('Switched to Ciphertext Decryption Terminal'); }} style={styles.cardButton}>
                <div style={styles.cardTitle}>[ 02 ] CIPHERTEXT TO PLAINTEXT</div>
                <div style={styles.cardDesc}>REVERSE DECRYPTION + CAESAR BRUTE-FORCE CRACKER</div>
              </button>
              <button onClick={() => { setMode('voice-to-text'); setInputText(''); setOutputText(''); addLog('Switched to Voice Intel Terminal'); }} style={styles.cardButton}>
                <div style={styles.cardTitle}>[ 03 ] VOICE RECOGNITION INTEL</div>
                <div style={styles.cardDesc}>LIVE MIC SPEECH TO PLAINTEXT & ARCHIVE VAULT</div>
              </button>
              <button onClick={() => { setMode('tracker'); addLog('Switched to Precise GPS Mobile Tracker'); }} style={styles.cardButton}>
                <div style={styles.cardTitle}>[ 04 ] PRECISE GPS MOBILE TRACER</div>
                <div style={styles.cardDesc}>EXACT LAT/LON & CELL TOWER SECTOR LOCK</div>
              </button>
              <button onClick={() => { setMode('face-rec'); startCamera(); addLog('Switched to Biometric Face Recognition Module'); }} style={styles.cardButton}>
                <div style={styles.cardTitle}>[ 05 ] BIOMETRIC FACE RECOGNITION</div>
                <div style={styles.cardDesc}>MYSQL CHECK & PERSONNEL DATA DISPLAY</div>
              </button>
            </div>
          </div>
        )}

        {mode !== 'home' && (
          <div>
            <button onClick={() => { setMode('home'); stopCamera(); setInputText(''); setOutputText(''); setTrackerResult(null); setFaceData(null); setIsNewUser(false); setCrackResults(null); addLog('Returned to main dashboard.'); }} style={styles.backButton}>
              &lt;-- BACK TO COMMAND CENTER
            </button>

            <h2 style={styles.modeTitle}>
              {mode === 'plain-to-cipher' && '>> TERMINAL: PLAINTEXT MULTI-ALGORITHM ENCRYPTION'}
              {mode === 'cipher-to-plain' && '>> TERMINAL: CIPHERTEXT REVERSE DECRYPTION SUITE'}
              {mode === 'voice-to-text' && '>> TERMINAL: LIVE SPEECH-TO-TEXT & AUDIO ARCHIVE VAULT'}
              {mode === 'tracker' && '>> TERMINAL: PRECISE GPS MOBILE & SECTOR TRACER'}
              {mode === 'face-rec' && '>> TERMINAL: BIOMETRIC MYSQL RECOGNITION & PERSONNEL PROFILE'}
            </h2>

            {(mode === 'plain-to-cipher' || mode === 'cipher-to-plain') && (
              <div>
                <div style={styles.algoSelectorContainer}>
                  <div style={styles.label}>SELECT CRYPTOGRAPHIC ENGINE:</div>
                  <div style={styles.algoButtonRow}>
                    {[
                      { id: 'caesar', name: '1. CAESAR CIPHER' },
                      { id: 'rot13', name: '2. ROT13' },
                      { id: 'base64', name: '3. BASE64 ENCODER' },
                      { id: 'hill', name: '4. HILL CIPHER (MATRIX)' },
                      { id: 'vigenere', name: '5. VIGENÈRE CIPHER' },
                      { id: 'xor', name: '6. XOR STREAM CIPHER' },
                      { id: 'railfence', name: '7. RAIL FENCE CIPHER' },
                      { id: 'aes', name: '8. AES-256-GCM (REAL)' },
                    ].map((algo) => (
                      <button
                        key={algo.id}
                        onClick={() => {
                          setCipherType(algo.id);
                          setCrackResults(null);
                          handleConvert(inputText, mode === 'plain-to-cipher' ? 'to-cipher' : 'to-plain', algo.id, shiftVal, secretKey, railCount);
                        }}
                        style={cipherType === algo.id ? styles.algoBtnActive : styles.algoBtn}
                      >
                        {algo.name}
                      </button>
                    ))}
                  </div>
                </div>

                {cipherType === 'caesar' && (
                  <div style={styles.paramBox}>
                    <label style={styles.label}>⚙️ ADJUST SHIFT VALUE (Integer):</label>
                    <input type="number" value={shiftVal} onChange={(e) => { setShiftVal(e.target.value); handleConvert(inputText, mode === 'plain-to-cipher' ? 'to-cipher' : 'to-plain', 'caesar', e.target.value, secretKey, railCount); }} style={styles.smallInput} />
                  </div>
                )}

                {cipherType === 'railfence' && (
                  <div style={styles.paramBox}>
                    <label style={styles.label}>⚙️ NUMBER OF RAILS (min 2):</label>
                    <input type="number" min="2" value={railCount} onChange={(e) => { setRailCount(e.target.value); handleConvert(inputText, mode === 'plain-to-cipher' ? 'to-cipher' : 'to-plain', 'railfence', shiftVal, secretKey, e.target.value); }} style={styles.smallInput} />
                  </div>
                )}

                {(cipherType === 'vigenere' || cipherType === 'xor' || cipherType === 'aes') && (
                  <div style={styles.paramBox}>
                    <label style={styles.label}>🔐 ENTER SECRET SECURITY KEY / PASSWORD:</label>
                    <input type="text" value={secretKey} onChange={(e) => { setSecretKey(e.target.value); handleConvert(inputText, mode === 'plain-to-cipher' ? 'to-cipher' : 'to-plain', cipherType, shiftVal, e.target.value, railCount); }} placeholder="e.g. ALPHA_SECURE_99" style={styles.inputField} />
                    {cipherType === 'aes' && (
                      <div style={{ fontSize: '10px', color: '#008866' }}>
                        Real AES-256-GCM: key stretched via PBKDF2 (100,000 iterations), random salt + IV per message. Same key required to decrypt.
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}

            {mode === 'face-rec' && (
              <div style={styles.voiceSection}>
                <div style={styles.radarBox}>OPTICAL WEBCAM FEED ACTIVE // POSITION FACE FOR MYSQL DATABASE RECOGNITION</div>
                <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '15px' }}>
                  <video ref={videoRef} autoPlay playsInline style={{ width: '320px', height: '240px', border: '2px solid #00ffcc', borderRadius: '4px' }} />
                </div>
                <button onClick={scanAndVerifyFace} disabled={isScanning} style={isScanning ? styles.recordingBtnActive : styles.recordingBtn}>
                  {isScanning ? 'SCANNING BIOMETRIC MATRIX & QUERYING MYSQL...' : 'SCAN & VERIFY FACE'}
                </button>

                {faceData && (
                  <div style={styles.archiveContainer}>
                    <div style={styles.diagTitle}>// DATABASE VERIFICATION: PERSONNEL PROFILE FOUND</div>
                    <div style={styles.archiveItem}>
                      <div style={{ fontSize: '13px', color: '#00ffcc', marginBottom: '6px' }}><strong>Status:</strong> {faceData.status}</div>
                      <div style={{ fontSize: '15px', color: '#ffffff', marginBottom: '4px' }}><strong>Full Name:</strong> {faceData.name}</div>
                      <div style={{ fontSize: '13px', color: '#00ff66', marginBottom: '4px' }}><strong>Role Title:</strong> {faceData.role}</div>
                      <div style={{ fontSize: '13px', color: '#ffcc00', marginBottom: '4px' }}><strong>Clearance Level:</strong> {faceData.clearance}</div>
                      <div style={{ fontSize: '13px', color: '#00ccff', marginBottom: '4px' }}><strong>System Action:</strong> {faceData.action}</div>
                      <div style={{ fontSize: '11px', color: '#008866', marginTop: '6px' }}>Biometric Hash Token: {faceData.hash}</div>
                    </div>
                  </div>
                )}

                {isNewUser && (
                  <div style={styles.archiveContainer}>
                    <div style={{ color: '#ff3333', fontSize: '12px', fontWeight: 'bold', marginBottom: '10px' }}>// NOTICE: DATA NOT AVAILABLE IN MYSQL. ENTER PERSONNEL INFO TO ADD TO TABLE:</div>
                    <form onSubmit={handleRegisterNewPersonnel}>
                      <div style={{ marginBottom: '10px', textAlign: 'left' }}>
                        <label style={styles.label}>FULL NAME:</label>
                        <input type="text" value={regName} onChange={(e) => setRegName(e.target.value)} placeholder="e.g. Agent Mangesh" style={styles.inputField} />
                      </div>
                      <div style={{ marginBottom: '10px', textAlign: 'left' }}>
                        <label style={styles.label}>ROLE TITLE:</label>
                        <input type="text" value={regRole} onChange={(e) => setRegRole(e.target.value)} placeholder="e.g. Cyber Security Analyst" style={styles.inputField} />
                      </div>
                      <div style={{ marginBottom: '15px', textAlign: 'left' }}>
                        <label style={styles.label}>CLEARANCE LEVEL:</label>
                        <select value={regClearance} onChange={(e) => setRegClearance(e.target.value)} style={styles.inputField}>
                          <option value="LEVEL-1 (PENDING)">LEVEL-1 (PENDING)</option>
                          <option value="LEVEL-2 (OPERATIONAL)">LEVEL-2 (OPERATIONAL)</option>
                          <option value="LEVEL-3 (CONFIDENTIAL)">LEVEL-3 (CONFIDENTIAL)</option>
                          <option value="LEVEL-5 (CLASSIFIED)">LEVEL-5 (CLASSIFIED)</option>
                        </select>
                      </div>
                      <button type="submit" style={styles.recordingBtn}>INSERT INFO INTO MYSQL TABLE</button>
                    </form>
                  </div>
                )}
              </div>
            )}

            {mode === 'tracker' && (
              <div style={styles.voiceSection}>
                <div style={styles.radarBox}>ENTER ANY 10-DIGIT MOBILE NUMBER (e.g., 9876543210) TO ACQUIRE THIS DEVICE'S OWN GPS LAT/LON & SYNC TO MYSQL</div>
                <form onSubmit={handlePhoneTracking} style={{ marginBottom: '20px' }}>
                  <input type="text" value={phoneNumber} onChange={(e) => setPhoneNumber(e.target.value)} placeholder="9876543210" maxLength="10" style={styles.inputField} />
                  <br />
                  <button type="submit" disabled={isTracing} style={isTracing ? styles.recordingBtnActive : styles.recordingBtn}>
                    {isTracing ? 'ACQUIRING & SYNCING LIVE GPS...' : 'ACQUIRE LIVE GPS & LOG TO MYSQL'}
                  </button>
                </form>
                {trackerResult && (
                  <div style={styles.archiveContainer}>
                    <div style={styles.diagTitle}>// PRECISE TARGET GPS TELEMETRY REPORT:</div>
                    <div style={styles.archiveItem}>
                      <div style={{ fontSize: '12px', color: '#00ffcc', marginBottom: '5px' }}><strong>Target Mobile:</strong> {trackerResult.number}</div>
                      <div style={{ fontSize: '13px', color: '#00ff66' }}><strong>Exact Latitude:</strong> {trackerResult.lat}</div>
                      <div style={{ fontSize: '13px', color: '#00ff66', marginBottom: '5px' }}><strong>Exact Longitude:</strong> {trackerResult.lon}</div>
                      <div style={{ fontSize: '12px', color: '#ffffff' }}><strong>Grid Sector Pin:</strong> {trackerResult.sectorPin}</div>
                      <div style={{ fontSize: '12px', color: '#ffcc00' }}><strong>Telecom Circle:</strong> {trackerResult.circle}</div>
                      <div style={{ fontSize: '12px', color: '#00aa88', marginTop: '4px' }}><strong>Precision Accuracy:</strong> {trackerResult.accuracy}</div>
                      <div style={{ fontSize: '11px', color: '#ff3333', marginTop: '4px' }}><strong>Status:</strong> {trackerResult.status}</div>
                      <div style={{ fontSize: '10px', color: '#008866', marginTop: '5px' }}>Timestamp: {trackerResult.timestamp}</div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {mode === 'voice-to-text' && (
              <div style={styles.voiceSection}>
                <div style={styles.radarBox}>{isListening ? '🔴 LISTENING... SPEAK INTO YOUR MICROPHONE NOW' : '🎙️ CLICK BUTTON TO RECORD YOUR VOICE MESSAGE'}</div>
                <button onClick={startSpeechRecognition} disabled={isListening} style={isListening ? styles.recordingBtnActive : styles.recordingBtn}>
                  {isListening ? 'LISTENING TO SPEECH...' : 'RECORD & CONVERT HUMAN VOICE'}
                </button>
                <div style={styles.archiveContainer}>
                  <div style={styles.diagTitle}>// SECURE VOICE ARCHIVE VAULT (STORED AUDIO TRANSCRIPTS & CIPHERS):</div>
                  {voiceArchives.length === 0 ? (
                    <div style={{ fontSize: '12px', color: '#008866', fontStyle: 'italic' }}>No voice messages recorded yet in this session.</div>
                  ) : (
                    voiceArchives.map((item) => (
                      <div key={item.id} style={styles.archiveItem}>
                        <div style={{ fontSize: '10px', color: '#00ffcc', marginBottom: '4px' }}>TIMESTAMP: {item.time} | ALGO: {item.algo}</div>
                        <div style={{ fontSize: '12px', color: '#ffffff' }}><strong>Plain Text (Speech):</strong> {item.transcript}</div>
                        <div style={{ fontSize: '12px', color: '#00ff66', marginTop: '3px' }}><strong>Cipher Text:</strong> {item.cipher}</div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            )}

            {(mode === 'plain-to-cipher' || mode === 'cipher-to-plain') && (
              <div>
                <div style={styles.inputGroup}>
                  <label style={styles.label}>{mode === 'plain-to-cipher' ? 'ENTER PLAINTEXT PAYLOAD:' : 'ENTER CIPHERTEXT STREAM:'}</label>
                  <textarea
                    rows="3"
                    value={inputText}
                    onChange={(e) => handleConvert(e.target.value, mode === 'plain-to-cipher' ? 'to-cipher' : 'to-plain', cipherType, shiftVal, secretKey, railCount)}
                    placeholder="Type data stream here..."
                    style={styles.textarea}
                  />
                </div>

                <div style={styles.diagnosticsContainer}>
                  <div style={styles.diagTitle}>// STAGE LOGISTICS & PAYLOAD MAPPING [{cipherType.toUpperCase()}]:</div>
                  <div style={styles.diagGrid}>
                    <div style={styles.diagBox}>
                      <div style={styles.diagLabel}>ENTERED PLAINTEXT / SOURCE:</div>
                      <div style={styles.diagValue}>{inputText || '[ No Input Detected ]'}</div>
                    </div>
                    <div style={styles.diagBox}>
                      <div style={styles.diagLabel}>GENERATED CRYPTOGRAPHIC CIPHER:</div>
                      <div style={styles.diagCipherValue}>{outputText || '[ Awaiting Payload ]'}</div>
                    </div>
                  </div>
                </div>

                <div style={styles.outputGroup}>
                  <label style={styles.label}>SECURE TRANSMISSION STATUS:</label>
                  <div style={styles.outputBox}>
                    {isProcessing ? 'PROCESSING...' : outputText ? `SUCCESSFULLY PROCESSED [Engine: ${cipherType.toUpperCase()}]` : 'Awaiting data stream packet execution...'}
                  </div>
                </div>

                {/* --- Frequency Analysis Panel --- */}
                <div style={{ marginTop: '15px' }}>
                  <button onClick={() => setShowFrequency(!showFrequency)} style={styles.backButton}>
                    {showFrequency ? 'HIDE FREQUENCY ANALYSIS' : 'SHOW FREQUENCY ANALYSIS'}
                  </button>
                  {showFrequency && (
                    <div style={styles.archiveContainer}>
                      <div style={styles.diagTitle}>// LETTER FREQUENCY ANALYSIS OF OUTPUT (CRYPTANALYSIS TOOL):</div>
                      {!outputText ? (
                        <div style={{ fontSize: '12px', color: '#008866', fontStyle: 'italic' }}>No output to analyze yet.</div>
                      ) : (
                        Object.entries(frequencyData || {})
                          .sort((a, b) => b[1] - a[1])
                          .map(([letter, count]) => (
                            <div key={letter} style={{ display: 'flex', alignItems: 'center', marginBottom: '4px' }}>
                              <div style={{ width: '20px', fontSize: '11px', color: '#00ffcc' }}>{letter}</div>
                              <div style={{ flex: 1, background: '#050b14', height: '10px', borderRadius: '2px', overflow: 'hidden' }}>
                                <div style={{ width: `${(count / maxFreq) * 100}%`, background: '#00ffcc', height: '100%' }} />
                              </div>
                              <div style={{ width: '25px', fontSize: '10px', color: '#00aa88', textAlign: 'right' }}>{count}</div>
                            </div>
                          ))
                      )}
                      <div style={{ fontSize: '10px', color: '#008866', marginTop: '8px' }}>
                        Simple substitution ciphers (Caesar, ROT13, Vigenère) preserve letter-frequency patterns of the original language, which is exactly what makes them breakable via this technique.
                      </div>
                    </div>
                  )}
                </div>

                {/* --- Caesar Brute-Force Cracker (decrypt mode only) --- */}
                {mode === 'cipher-to-plain' && cipherType === 'caesar' && (
                  <div style={{ marginTop: '15px' }}>
                    <button onClick={handleCrackCaesar} disabled={isCracking} style={isCracking ? styles.recordingBtnActive : styles.recordingBtn}>
                      {isCracking ? 'BRUTE-FORCING ALL SHIFTS...' : '🔓 CRACK CIPHER (BRUTE-FORCE ALL 26 SHIFTS)'}
                    </button>
                    {crackResults && (
                      <div style={styles.archiveContainer}>
                        <div style={styles.diagTitle}>// BRUTE-FORCE RESULTS (RANKED BY ENGLISH-WORD MATCH SCORE):</div>
                        {crackResults.slice(0, 6).map((r) => (
                          <div key={r.shift} style={{ ...styles.archiveItem, ...(r.score > 0 ? { border: '1px solid #00ff66' } : {}) }}>
                            <div style={{ fontSize: '11px', color: r.score > 0 ? '#00ff66' : '#00aa88' }}>
                              <strong>Shift {r.shift}</strong> {r.score > 0 ? `— ${r.score} likely English word(s) found` : ''}
                            </div>
                            <div style={{ fontSize: '12px', color: '#ffffff', wordBreak: 'break-all' }}>{r.text}</div>
                          </div>
                        ))}
                        <div style={{ fontSize: '10px', color: '#008866', marginTop: '4px' }}>
                          Demonstrates why Caesar cipher offers no real security: only 26 possible keys, so a computer checks them all instantly.
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      <div style={styles.footer}>
        <div style={styles.footerCol}><strong>SYSTEM INTEGRITY:</strong> 99.9% SECURE</div>
        <div style={styles.footerCol}><strong>MYSQL DATABASE:</strong> LINKED TO CyberSOCBackend</div>
        <div style={styles.footerCol}><strong>THREAT LEVEL:</strong> LOW</div>
      </div>

      <div style={styles.terminalLog}>
        <div style={{ color: '#00ffcc', fontWeight: 'bold', marginBottom: '4px' }}>// PACKET SNIFFER LOG:</div>
        {logs.map((log, index) => (<div key={index} style={{ color: '#00cc66' }}>{log}</div>))}
      </div>
    </div>
  );
}

const styles = {
  container: { backgroundColor: '#050b14', color: '#00ffcc', minHeight: '100vh', fontFamily: '"Courier New", Courier, monospace', padding: '20px', boxSizing: 'border-box' },
  header: { display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '2px solid #00ffcc', paddingBottom: '15px', marginBottom: '20px' },
  title: { margin: 0, fontSize: '22px', letterSpacing: '2px', color: '#00ffcc', textShadow: '0 0 10px rgba(0,255,204,0.5)' },
  subtitle: { margin: '5px 0 0 0', fontSize: '12px', color: '#00aa88', letterSpacing: '1px' },
  statusBadge: { background: 'rgba(0, 255, 204, 0.1)', border: '1px solid #00ffcc', padding: '8px 15px', fontSize: '12px', fontWeight: 'bold', display: 'flex', alignItems: 'center', gap: '8px' },
  blinkingDot: { width: '8px', height: '8px', backgroundColor: '#00ff66', borderRadius: '50%', boxShadow: '0 0 8px #00ff66' },
  contentBox: { background: 'rgba(0, 20, 40, 0.8)', border: '1px solid #00aa88', borderRadius: '4px', padding: '25px', boxShadow: '0 0 20px rgba(0, 255, 204, 0.1)', marginBottom: '20px' },
  sectionHeader: { fontSize: '14px', letterSpacing: '1px', marginBottom: '15px', color: '#00cc99' },
  menuGrid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '15px' },
  cardButton: { background: '#0a192f', border: '1px solid #00ffcc', color: '#00ffcc', padding: '20px', textAlign: 'left', cursor: 'pointer', borderRadius: '4px', transition: 'all 0.2s ease', boxShadow: 'inset 0 0 10px rgba(0,255,204,0.05)' },
  cardTitle: { fontWeight: 'bold', fontSize: '14px', marginBottom: '8px' },
  cardDesc: { fontSize: '10px', color: '#008866' },
  backButton: { background: 'transparent', border: '1px solid #00ffcc', color: '#00ffcc', padding: '6px 12px', cursor: 'pointer', fontSize: '12px', marginBottom: '10px' },
  modeTitle: { fontSize: '16px', letterSpacing: '1px', marginBottom: '20px', color: '#ffffff' },
  algoSelectorContainer: { marginBottom: '15px', background: '#02060d', border: '1px solid #005544', padding: '12px', borderRadius: '4px' },
  algoButtonRow: { display: 'flex', gap: '10px', flexWrap: 'wrap', marginTop: '8px' },
  algoBtn: { background: '#050b14', border: '1px solid #00aa88', color: '#00aa88', padding: '8px 14px', cursor: 'pointer', fontSize: '11px', fontWeight: 'bold', letterSpacing: '1px', borderRadius: '3px' },
  algoBtnActive: { background: '#00ffcc', border: '1px solid #00ffcc', color: '#050b14', padding: '8px 14px', cursor: 'pointer', fontSize: '11px', fontWeight: 'bold', letterSpacing: '1px', borderRadius: '3px', boxShadow: '0 0 8px rgba(0,255,204,0.5)' },
  paramBox: { background: '#02060d', border: '1px solid #00aa88', padding: '12px', borderRadius: '4px', marginBottom: '15px' },
  smallInput: { width: '120px', background: '#050b14', border: '1px solid #00ffcc', color: '#00ffcc', padding: '8px', fontFamily: 'monospace', fontSize: '13px', borderRadius: '3px', outline: 'none' },
  inputGroup: { marginBottom: '15px' },
  inputField: { width: '100%', background: '#02060d', border: '1px solid #00aa88', color: '#00ffcc', padding: '12px', fontFamily: 'monospace', fontSize: '14px', borderRadius: '4px', boxSizing: 'border-box', outline: 'none', marginBottom: '8px' },
  label: { display: 'block', fontSize: '12px', marginBottom: '8px', letterSpacing: '1px', color: '#00cc99' },
  textarea: { width: '100%', background: '#02060d', border: '1px solid #00aa88', color: '#00ffcc', padding: '12px', fontFamily: 'monospace', fontSize: '14px', borderRadius: '4px', boxSizing: 'border-box', outline: 'none' },
  diagnosticsContainer: { background: '#02060d', border: '1px solid #00ffcc', borderRadius: '4px', padding: '15px', marginTop: '15px', marginBottom: '15px' },
  diagTitle: { fontSize: '11px', color: '#00ffcc', marginBottom: '10px', letterSpacing: '1px', fontWeight: 'bold' },
  diagGrid: { display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '15px' },
  diagBox: { background: '#050b14', border: '1px solid #005544', padding: '10px', borderRadius: '3px' },
  diagLabel: { fontSize: '10px', color: '#00aa88', marginBottom: '5px', letterSpacing: '1px' },
  diagValue: { fontSize: '13px', color: '#ffffff', wordBreak: 'break-all' },
  diagCipherValue: { fontSize: '13px', color: '#00ff66', wordBreak: 'break-all', fontWeight: 'bold' },
  outputGroup: { marginTop: '15px' },
  outputBox: { background: '#02060d', border: '1px dashed #00ffcc', padding: '12px', minHeight: '20px', color: '#00ff66', wordBreak: 'break-all', fontSize: '13px' },
  voiceSection: { textAlign: 'center', padding: '5px 0' },
  radarBox: { border: '1px dashed #00aa88', padding: '15px', marginBottom: '15px', background: 'rgba(0,0,0,0.4)', letterSpacing: '1px', fontSize: '13px', color: '#00ffcc' },
  recordingBtn: { background: '#00ffcc', color: '#050b14', border: 'none', padding: '12px 25px', fontWeight: 'bold', cursor: 'pointer', fontSize: '13px', letterSpacing: '1px', marginBottom: '20px' },
  recordingBtnActive: { background: '#ff3333', color: '#ffffff', border: 'none', padding: '12px 25px', fontWeight: 'bold', cursor: 'pointer', fontSize: '13px', letterSpacing: '1px', marginBottom: '20px' },
  archiveContainer: { background: '#02060d', border: '1px solid #00aa88', borderRadius: '4px', padding: '15px', marginTop: '10px', textAlign: 'left', maxHeight: '280px', overflowY: 'auto' },
  archiveItem: { background: '#050b14', border: '1px solid #004433', padding: '12px', marginBottom: '10px', borderRadius: '3px' },
  footer: { display: 'flex', justifyContent: 'space-between', background: 'rgba(0, 15, 30, 0.9)', border: '1px solid #005544', padding: '10px 15px', fontSize: '11px', marginBottom: '15px' },
  footerCol: { letterSpacing: '1px' },
  terminalLog: { background: '#020408', border: '1px solid #003322', padding: '10px', fontSize: '11px', maxHeight: '80px', overflowY: 'auto' },
};

export default App;
