
        'use strict';
        /* ============================================================
           DORKCOIN NETWORK PARAMETERS
           ============================================================ */
        const DORK_PUBKEY_VERSION = 0x1e; // 30 → address starts with "D"
        const DORK_WIF_VERSION = 0x9e; // 158 → WIF compressed starts with "Q"
        const USE_COMPRESSED = true; // Must be true for Dorkcoin Core
        /* ============================================================
           secp256k1 CURVE (BigInt)
           ============================================================ */
        const P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
        const N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
        const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
        const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

        function modInv(a, m) {
          let old_r = ((a % m) + m) % m,
            r = m;
          let old_s = 1n,
            s = 0n;
          while (r !== 0n) {
            let q = old_r / r;
            [old_r, r] = [r, old_r - q * r];
            [old_s, s] = [s, old_s - q * s];
          }
          return ((old_s % m) + m) % m;
        }

        function ecAdd(p1, p2) {
          if (!p1) return p2;
          if (!p2) return p1;
          const [x1, y1] = p1, [x2, y2] = p2;
          let lam;
          if (x1 === x2) {
            if ((y1 + y2) % P_CURVE === 0n) return null;
            lam = (3n * x1 * x1) * modInv(2n * y1, P_CURVE) % P_CURVE;
          } else {
            lam = ((y2 - y1) % P_CURVE + P_CURVE) % P_CURVE * modInv((x2 - x1 + P_CURVE) % P_CURVE, P_CURVE) % P_CURVE;
          }
          const x3 = (lam * lam - x1 - x2) % P_CURVE;
          const y3 = (lam * (x1 - x3) - y1) % P_CURVE;
          return [(x3 + P_CURVE) % P_CURVE, (y3 + P_CURVE) % P_CURVE];
        }

        function ecMul(k, p) {
          let r = null,
            add = p;
          k = ((k % N_CURVE) + N_CURVE) % N_CURVE;
          while (k > 0n) {
            if (k & 1n) r = ecAdd(r, add);
            add = ecAdd(add, add);
            k >>= 1n;
          }
          return r;
        }

        function pubkeyCompressed(privHex) {
          const k = BigInt('0x' + privHex);
          const pt = ecMul(k, [Gx, Gy]);
          const prefix = (pt[1] % 2n === 0n) ? '02' : '03';
          return prefix + pt[0].toString(16).padStart(64, '0');
        }

        function pubkeyUncompressed(privHex) {
          const k = BigInt('0x' + privHex);
          const pt = ecMul(k, [Gx, Gy]);
          return '04' + pt[0].toString(16).padStart(64, '0') + pt[1].toString(16).padStart(64, '0');
        }
        async function sha256(dataHex) {
          const bytes = hexToBytes(dataHex);
          const hash = await crypto.subtle.digest('SHA-256', bytes);
          return bytesToHex(new Uint8Array(hash));
        }
        async function dblSha256(dataHex) {
          return sha256(await sha256(dataHex));
        }
        const B58C = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

        function b58encode(bytes) {
          let n = BigInt('0x' + bytesToHex(bytes));
          let res = '';
          while (n > 0n) {
            const r = n % 58n;
            n /= 58n;
            res = B58C[Number(r)] + res;
          }
          for (let i = 0; i < bytes.length && bytes[i] === 0; i++) res = '1' + res;
          return res;
        }
        async function b58checkEncode(payloadHex) {
          const chk = (await dblSha256(payloadHex)).slice(0, 8);
          return b58encode(hexToBytes(payloadHex + chk));
        }
        async function privToWIF(privHex) {
          const versionHex = DORK_WIF_VERSION.toString(16).padStart(2, '0');
          const suffix = USE_COMPRESSED ? '01' : '';
          return b58checkEncode(versionHex + privHex + suffix);
        }
        async function pubkeyToAddress(pubHex) {
          const sha = await sha256(pubHex);
          const ripe = ripemd160(hexToBytes(sha));
          const ripeHex = bytesToHex(ripe);
          const versionHex = DORK_PUBKEY_VERSION.toString(16).padStart(2, '0');
          return b58checkEncode(versionHex + ripeHex);
        }

// RIPEMD-160 menggunakan CryptoJS (sudah teruji)
function ripemd160(msg) {
    // msg adalah Uint8Array
    const wordArray = CryptoJS.lib.WordArray.create(msg);
    const hash = CryptoJS.RIPEMD160(wordArray);
    // Ubah hasil hash (WordArray) menjadi Uint8Array (20 byte)
    const result = new Uint8Array(20);
    for (let i = 0; i < 20; i++) {
        // Setiap word 32-bit, ambil byte yang sesuai
        result[i] = (hash.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return result;
}

        function hexToBytes(hex) {
          const b = new Uint8Array(hex.length / 2);
          for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.slice(i, i + 2), 16);
          return b;
        }

        function bytesToHex(b) {
          return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
        }
        /* ============================================================
           QR CODE HELPER
           ============================================================ */
        function renderQR(canvasId, text) {
          const canvas = document.getElementById(canvasId);
          if (!canvas || !text) return;
          // Clear canvas
          canvas.width = 180;
          canvas.height = 180;
          const ctx = canvas.getContext('2d');
          ctx.clearRect(0, 0, 180, 180);
          try {
            // Use qrcode.js library if available
            if (typeof QRCode !== 'undefined') {
              const qr = new QRCode(canvas, {
                text: text,
                width: 180,
                height: 180,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.M
              });
            }
          } catch (e) {
            // Fallback: draw text placeholder
            ctx.fillStyle = '#f8f9fa';
            ctx.fillRect(0, 0, 180, 180);
            ctx.fillStyle = '#666';
            ctx.font = '11px monospace';
            ctx.textAlign = 'center';
            ctx.fillText('QR unavailable', 90, 90);
          }
        }
        /* qrcode.js creates an img inside a div – we need a different approach for canvas IDs.
           Instead, we'll use a div-based QR and replace canvas approach. */
        function renderQRDiv(containerId, text) {
          const container = document.getElementById(containerId);
          if (!container || !text) return;
          container.innerHTML = '';
          if (typeof QRCode !== 'undefined') {
            new QRCode(container, {
              text: text,
              width: 180,
              height: 180,
              colorDark: '#000000',
              colorLight: '#ffffff',
              correctLevel: QRCode.CorrectLevel.M
            });
          }
        }
        /* ============================================================
           WALLET GENERATION (direct random key, no mnemonic)
           ============================================================ */
        async function walletFromEntropy(entropy) {
          // Use raw entropy as private key (32 bytes)
          const privHex = bytesToHex(entropy);
          const pubHex = USE_COMPRESSED ? pubkeyCompressed(privHex) : pubkeyUncompressed(privHex);
          const address = await pubkeyToAddress(pubHex);
          const wif = await privToWIF(privHex);
          return {
            privHex,
            pubHex,
            address,
            wif
          };
        }
        async function walletFromPrivateKey(wif) {
          const decoded = (() => {
            const bytes = (() => {
              let n = 0n;
              for (let c of wif) {
                const idx = B58C.indexOf(c);
                if (idx === -1) throw new Error('Invalid base58 char');
                n = n * 58n + BigInt(idx);
              }
              const bytes = [];
              while (n > 0n) {
                bytes.unshift(Number(n & 0xFFn));
                n >>= 8n;
              }
              return new Uint8Array(bytes);
            })();
            let leading = 0;
            while (leading < wif.length && wif[leading] === '1') leading++;
            const result = new Uint8Array(bytes.length + leading);
            result.set(bytes, leading);
            return result;
          })();
          const checksum = decoded.slice(-4);
          const payload = decoded.slice(0, -4);
          const chkCalc = (await dblSha256(bytesToHex(payload))).slice(0, 8);
          if (bytesToHex(checksum) !== chkCalc) throw new Error('Invalid WIF checksum');
          const version = payload[0];
          if (version !== DORK_WIF_VERSION) throw new Error(`Invalid version byte: expected ${DORK_WIF_VERSION}, got ${version}`);
          let privHex = bytesToHex(payload.slice(1, 33));
          const hasCompression = payload.length === 34 && payload[33] === 0x01;
          const pubHex = hasCompression ? pubkeyCompressed(privHex) : pubkeyUncompressed(privHex);
          const address = await pubkeyToAddress(pubHex);
          const wifCorrected = await privToWIF(privHex);
          return {
            privHex,
            pubHex,
            address,
            wif: wifCorrected,
            compressed: hasCompression
          };
        }
        /* ===== UI ===== */
        function copyEl(id) {
          const el = document.getElementById(id);
          if (el) navigator.clipboard.writeText(el.innerText);
        }

        function hideErr(id) {
          const err = document.getElementById(id);
          if (err) err.classList.remove('show');
        }

        function switchTab(tab, btn) {
          if (typeof bootstrap !== 'undefined' && bootstrap.Tab) {
            new bootstrap.Tab(btn).show();
          } else {
            document.querySelectorAll('.tab-pane').forEach(t => t.classList.remove('show', 'active'));
            document.getElementById(`${tab}-tab`).classList.add('show', 'active');
            document.querySelectorAll('.nav-link').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
          }
        }
        let lastGeneratedWallet = null;
        async function generateWallet() {
          const entropy = crypto.getRandomValues(new Uint8Array(32));
          const w = await walletFromEntropy(entropy);
          lastGeneratedWallet = w;
          document.getElementById('address-display').innerText = w.address;
          document.getElementById('seed-display').innerText = w.wif;
          document.getElementById('public-key-display').innerText = w.pubHex;
          document.getElementById('generated-wallet').style.display = 'block';
          // Render QR codes
          setTimeout(() => {
            renderQRDiv('gen-address-qr', w.address);
            renderQRDiv('gen-privkey-qr', w.wif);
          }, 50);
          // Fill debug info
          const debugDiv = document.getElementById('debug-info');
          if (debugDiv) {
            const uncompPub = pubkeyUncompressed(w.privHex);
            const uncompAddr = await pubkeyToAddress(uncompPub);
            debugDiv.innerHTML = `
      
							<strong>🔍 Comparison (for debugging):</strong>
							<br>
      Compressed address (used by Dorkcoin Core): ${w.address}
								<br>
      Uncompressed address (would be different): ${uncompAddr}
									<br>
										<span style="color: var(--dork-secondary);">✅ If the core wallet shows a different address, it means it expects uncompressed keys. Please report this to the developer.</span>
    `;
          }
        }

        function toggleDebug() {
          const debug = document.getElementById('debug-info');
          if (debug) debug.style.display = debug.style.display === 'none' ? 'block' : 'none';
        }
        async function recoverFromWif() {
          const wif = document.getElementById('recovery-wif').value.trim();
          const errDiv = document.getElementById('wif-error');
          try {
            const w = await walletFromPrivateKey(wif);
            document.getElementById('recovered-address').innerText = w.address;
            document.getElementById('recovered-seed').innerText = w.wif;
            document.getElementById('recovered-public-key').innerText = w.pubHex;
            const statusDiv = document.getElementById('recovery-checksum-status');
            statusDiv.innerText = `✓ Wallet recovered from private key (${w.compressed ? 'compressed' : 'uncompressed'})`;
            statusDiv.className = 'checksum-status cs-ok';
            statusDiv.style.display = 'block';
            document.getElementById('recovered-wallet').style.display = 'block';
            errDiv.classList.remove('show');
            // Render QR codes
            setTimeout(() => {
              renderQRDiv('rec-address-qr', w.address);
              renderQRDiv('rec-privkey-qr', w.wif);
            }, 50);
          } catch (e) {
            errDiv.innerText = e.message;
            errDiv.classList.add('show');
            document.getElementById('recovered-wallet').style.display = 'none';
          }
        }
        /* ===== Vanity Address Search ===== */
        let vanityStop = false;
        let vanityTimeout = null;
        let vanityStartTime = 0;
        let vanityAttempts = 0;
        let vanityMaxAttempts = 0;

        function updateVanityStats() {
          const elapsed = (Date.now() - vanityStartTime) / 1000;
          const speed = vanityAttempts / elapsed;
          document.getElementById('attempts-count').innerText = vanityAttempts.toLocaleString();
          document.getElementById('speed-count').innerText = Math.round(speed).toLocaleString();
          document.getElementById('elapsed-time').innerText = elapsed.toFixed(1) + 's';
          const progress = Math.min(100, (vanityAttempts / vanityMaxAttempts) * 100);
          document.getElementById('vanity-progress-bar').style.width = progress + '%';
        }
        async function startVanitySearch() {
          if (vanityTimeout) return;
          const pattern = document.getElementById('vanity-pattern').value.trim();
          if (!pattern) {
            alert('Please enter a pattern to search.');
            return;
          }
          vanityMaxAttempts = parseInt(document.getElementById('max-attempts').value, 10);
          const position = document.getElementById('vanity-position').value;
          const caseSensitive = document.getElementById('case-sensitive').value === 'true';
          const searchPattern = caseSensitive ? pattern : pattern.toLowerCase();
          const addressPrefix = 'DORK1';
          vanityStop = false;
          vanityAttempts = 0;
          vanityStartTime = Date.now();
          document.getElementById('vanity-progress').style.display = 'block';
          document.getElementById('vanity-result').style.display = 'none';
          const updateInterval = setInterval(() => updateVanityStats(), 200);
          for (let i = 0; i < vanityMaxAttempts; i++) {
            if (vanityStop) break;
            const entropy = crypto.getRandomValues(new Uint8Array(32));
            const wallet = await walletFromEntropy(entropy);
            const addr = wallet.address;
            const addrWithoutPrefix = addr.slice(addressPrefix.length);
            const checkAddr = caseSensitive ? addrWithoutPrefix : addrWithoutPrefix.toLowerCase();
            let found = false;
            if (position === 'start') {
              found = checkAddr.startsWith(searchPattern);
            } else {
              found = checkAddr.includes(searchPattern);
            }
            if (found) {
              document.getElementById('vanity-address').innerText = wallet.address;
              document.getElementById('vanity-seed').innerText = wallet.wif;
              document.getElementById('vanity-public-key').innerText = wallet.pubHex;
              document.getElementById('vanity-result').style.display = 'block';
              vanityStop = true;
              // Render QR codes
              setTimeout(() => {
                renderQRDiv('vanity-address-qr', wallet.address);
                renderQRDiv('vanity-privkey-qr', wallet.wif);
              }, 50);
              break;
            }
            vanityAttempts++;
            if (i % 100 === 0) await new Promise(r => setTimeout(r, 0));
          }
          clearInterval(updateInterval);
          vanityTimeout = null;
          document.getElementById('vanity-progress').style.display = 'none';
          if (!vanityStop) {
            alert('Vanity address not found within max trials. Try increasing max trials or a simpler pattern.');
          }
        }

        function stopVanitySearch() {
          vanityStop = true;
        }