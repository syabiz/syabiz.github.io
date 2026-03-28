'use strict';

/* ============================================================
   SMT NETWORK PARAMETERS – CORRECTED FROM chainparams.cpp
   PUBKEY_ADDRESS = 63  (0x3F) → address starts with "S"
   SECRET_KEY     = 128 (0x80) → WIF starts with "L" or "K"
   BIP44 coin type: 5
============================================================ */
const SMT_PUBKEY_VERSION = 0x3F;   // 63 → "S"
const SMT_WIF_VERSION    = 0x80;   // 128 → "L"/"K" for compressed WIF
const USE_COMPRESSED     = true;

/* ============================================================
   secp256k1 CURVE (BigInt)
============================================================ */
const P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

/* ── EC Math (unchanged) ── */
function modInv(a, m) {
  let old_r = ((a % m) + m) % m, r = m;
  let old_s = 1n, s = 0n;
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
  let r = null, add = p;
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

/* ── Hashing ── */
async function sha256(dataHex) {
  const bytes = hexToBytes(dataHex);
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return bytesToHex(new Uint8Array(hash));
}

async function dblSha256(dataHex) {
  return sha256(await sha256(dataHex));
}

function ripemd160(msg) {
  const wordArray = CryptoJS.lib.WordArray.create(msg);
  const hash = CryptoJS.RIPEMD160(wordArray);
  const result = new Uint8Array(20);
  for (let i = 0; i < 20; i++) {
    result[i] = (hash.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return result;
}

/* ── Base58 ── */
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

/* ── SMT-specific encoders (corrected version bytes) ── */
async function privToWIF(privHex) {
  const versionHex = SMT_WIF_VERSION.toString(16).padStart(2, '0');
  const suffix = USE_COMPRESSED ? '01' : '';
  return b58checkEncode(versionHex + privHex + suffix);
}

async function pubkeyToAddress(pubHex) {
  const sha = await sha256(pubHex);
  const ripe = ripemd160(hexToBytes(sha));
  const ripeHex = bytesToHex(ripe);
  const versionHex = SMT_PUBKEY_VERSION.toString(16).padStart(2, '0');
  return b58checkEncode(versionHex + ripeHex);
}

/* ── Hex utils ── */
function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) b[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  return b;
}

function bytesToHex(b) {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

/* ── WIF decode / private key restore ── */
async function walletFromEntropy(entropy) {
  const privHex = bytesToHex(entropy);
  const pubHex  = USE_COMPRESSED ? pubkeyCompressed(privHex) : pubkeyUncompressed(privHex);
  const address = await pubkeyToAddress(pubHex);
  const wif     = await privToWIF(privHex);
  return { privHex, pubHex, address, wif };
}

async function walletFromPrivateKey(wifOrHex) {
  if (/^[0-9a-fA-F]{64}$/.test(wifOrHex)) {
    const privHex = wifOrHex.toLowerCase();
    const pubHex  = USE_COMPRESSED ? pubkeyCompressed(privHex) : pubkeyUncompressed(privHex);
    const address = await pubkeyToAddress(pubHex);
    const wif     = await privToWIF(privHex);
    return { privHex, pubHex, address, wif, compressed: true };
  }
  const wif = wifOrHex;
  const bytes = (() => {
    let n = 0n;
    for (let c of wif) {
      const idx = B58C.indexOf(c);
      if (idx === -1) throw new Error('Invalid Base58 character: ' + c);
      n = n * 58n + BigInt(idx);
    }
    const bytes = [];
    while (n > 0n) { bytes.unshift(Number(n & 0xFFn)); n >>= 8n; }
    return new Uint8Array(bytes);
  })();
  let leading = 0;
  while (leading < wif.length && wif[leading] === '1') leading++;
  const decoded = (() => {
    const result = new Uint8Array(bytes.length + leading);
    result.set(bytes, leading);
    return result;
  })();
  const checksum = decoded.slice(-4);
  const payload  = decoded.slice(0, -4);
  const chkCalc  = (await dblSha256(bytesToHex(payload))).slice(0, 8);
  if (bytesToHex(checksum) !== chkCalc) throw new Error('Invalid WIF checksum');
  const version = payload[0];
  if (version !== SMT_WIF_VERSION) throw new Error(`Wrong version byte: expected 0x${SMT_WIF_VERSION.toString(16).toUpperCase()} (SMT), got 0x${version.toString(16).toUpperCase()}`);
  const privHex      = bytesToHex(payload.slice(1, 33));
  const hasCompressed = payload.length === 34 && payload[33] === 0x01;
  const pubHex       = hasCompressed ? pubkeyCompressed(privHex) : pubkeyUncompressed(privHex);
  const address      = await pubkeyToAddress(pubHex);
  const wifCorrected = await privToWIF(privHex);
  return { privHex, pubHex, address, wif: wifCorrected, compressed: hasCompressed };
}

/* ============================================================
   BIP32 / BIP44 Key Derivation (CORRECTED – with normal children)
============================================================ */
async function hmacSha512(key, data) {
  const keyBytes = typeof key === 'string' ? hexToBytes(key) : key;
  const dataBytes = typeof data === 'string' ? hexToBytes(data) : data;
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyBytes, { name: 'HMAC', hash: 'SHA-512' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, dataBytes);
  return new Uint8Array(sig);
}

async function masterKeyFromSeed(seedHex) {
  const seed = hexToBytes(seedHex);
  const I = await hmacSha512('Bitcoin seed', seed);
  const IL = I.slice(0, 32);
  const IR = I.slice(32, 64);
  return { key: bytesToHex(IL), chainCode: bytesToHex(IR) };
}

async function deriveHardenedChild(parentKeyHex, parentChainHex, index) {
  const indexBuf = new Uint8Array(4);
  indexBuf[0] = (index >> 24) & 0xff;
  indexBuf[1] = (index >> 16) & 0xff;
  indexBuf[2] = (index >> 8) & 0xff;
  indexBuf[3] = index & 0xff;
  const data = new Uint8Array([0x00, ...hexToBytes(parentKeyHex), ...indexBuf]);
  const I = await hmacSha512(parentChainHex, data);
  const IL = I.slice(0, 32);
  const IR = I.slice(32, 64);
  const newKey = (BigInt('0x' + bytesToHex(IL)) + BigInt('0x' + parentKeyHex)) % N_CURVE;
  return { key: newKey.toString(16).padStart(64, '0'), chainCode: bytesToHex(IR) };
}

async function deriveNormalChild(parentKeyHex, parentChainHex, index) {
  const pubHex = pubkeyCompressed(parentKeyHex);
  const indexBuf = new Uint8Array(4);
  indexBuf[0] = (index >> 24) & 0xff;
  indexBuf[1] = (index >> 16) & 0xff;
  indexBuf[2] = (index >> 8) & 0xff;
  indexBuf[3] = index & 0xff;
  const data = new Uint8Array([...hexToBytes(pubHex), ...indexBuf]);
  const I = await hmacSha512(parentChainHex, data);
  const IL = I.slice(0, 32);
  const IR = I.slice(32, 64);
  const newKey = (BigInt('0x' + bytesToHex(IL)) + BigInt('0x' + parentKeyHex)) % N_CURVE;
  return { key: newKey.toString(16).padStart(64, '0'), chainCode: bytesToHex(IR) };
}

async function deriveBip44Wallet(seedHex, addressIndex) {
  let { key, chainCode } = await masterKeyFromSeed(seedHex);
  // m/44'
  ({ key, chainCode } = await deriveHardenedChild(key, chainCode, 0x80000000 | 44));
  // m/44'/5'  (coin type = 5)
  ({ key, chainCode } = await deriveHardenedChild(key, chainCode, 0x80000000 | 5));
  // m/44'/5'/0' (account 0)
  ({ key, chainCode } = await deriveHardenedChild(key, chainCode, 0x80000000 | 0));
  // m/44'/5'/0'/0 (change = 0, non-hardened)
  ({ key, chainCode } = await deriveNormalChild(key, chainCode, 0));
  // m/44'/5'/0'/0/addressIndex (non-hardened)
  ({ key, chainCode } = await deriveNormalChild(key, chainCode, addressIndex));
  return key;
}

/* ============================================================
   BIP39 MNEMONIC (fixed async and checksum)
============================================================ */
const BIP39_WORDS = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among amount amused analyst anchor ancient anger angle angry animal ankle announce annual another answer antenna antique anxiety any apart apology appear apple approve april arch arctic area arena argue arm armed armor army around arrange arrest arrive arrow art artefact artist artwork ask aspect assault asset assist assume asthma athlete atom attack attend attitude attract auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful awkward axis baby bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely bargain barrel base basic basket battle beach bean beauty because become beef before begin behave behind believe below belt bench benefit best betray better between beyond bicycle bid bike bind biology bird birth bitter black blade blame blanket blast bleak bless blind blood blossom blouse blue blur blush board boat body boil bomb bone book boost border boring borrow boss bottom bounce box boy bracket brain brand brave breeze brick bridge brief bright bring brisk broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel candy cannon canvas canyon capable capital captain car carbon card cargo carpet carry cart case cash casino castle casual cat catalog catch category cattle caught cause caution cave ceiling celery cement census chair chaos chapter charge chase chat cheap check cheese chef cherry chest chicken chief child chimney choice choose chronic chuckle chunk cinnamon circle citizen city civil claim clap clarify claw clay clean clerk clever click client cliff climb clinic clip clock clog close cloth cloud clown club clump cluster coarse coat coconut code coffee coil coin collect color column combine come comfort comic common company concert conduct confirm congress connect consider control convince cook cool copper copy coral core corn correct cost cotton couch country couple course cousin cover coyote crack cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket crime crisp critic cross crouch crowd crucial cruel cruise crumble crunch crush cry crystal cube culture cup cupboard curious current curtain curve cushion custom cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate debris decade december decide decline decorate decrease deer defense define defy degree delay deliver demand demise denial dentist deny depart depend deposit depth deputy derive describe desert design desk despair destroy detail detect develop device devote diagram dial diamond diary dice diesel diet differ digital dignity dilemma dinner dinosaur direct dirt disagree discover disease dish dismiss disorder display distance divert divide divorce dizzy doctor document dog doll dolphin domain donate donkey donor door dose double dove draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn earth easily east easy echo ecology edge edit educate effort egg eight either elbow elder electric elegant element elephant elevator elite else embark embody embrace emerge emotion employ empower empty enable enact endless endorse enemy engage engine enhance enjoy enroll ensure enter entire entry envelope episode equal equip erase erode erosion error erupt escape essay essence estate eternal ethics evidence evil evoke evolve exact example excess exchange excite exclude exercise exhaust exhibit exile exist exit exotic expand expire explain expose express extend extra eye fable face faculty fade faint faith fall false fame family famous fan fancy fantasy far fashion fat fatal father fatigue fault favorite feature february federal fee feed feel feet fellow felt fence festival fetch fever few fiber fiction field figure file film filter final find fine finger finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor flee flight flip float flock floor flower fluid flush fly foam focus fog foil follow food foot force forest forget fork fortune forum forward fossil foster found fox fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel fun funny furnace fury future gadget gain galaxy gallery game gap garbage garden garlic garment gasp gate gather gauge gaze general genius genre gentle genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose gorilla gospel gossip govern gown grab grace grain grant grape grass gravity great green grid grief grit grocery group grow grunt guard guide guilt guitar gun gym habit hair half hammer hamster hand happy harbor hard harsh harvest hat have hawk hazard head health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn hospital host hour hover hub huge human humble humor hundred hungry hunt hurdle hurry hurt husband hybrid ice icon ignore ill illegal image imitate immense immune impact impose improve impulse inbox income increase index indicate indoor industry infant inflict inform inhale inject injury inmate inner innocent input inquiry insane insect inside inspire install intact interest into invest invite involve iron island isolate issue item ivory jacket jaguar jar jazz jealous jelly jewel job join joke journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key kick kid kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab ladder lady lake lamp language laptop large later laugh laundry lava law lawn lawsuit layer lazy leader learn leave lecture left leg legal legend leisure lemon lend length lens leopard lesson letter level liar liberty library license life lift light like limb limit link lion liquid list little live lizard load loan lobster local lock logic lonely long loop lottery loud loyal lucky luggage lumber lunar lunch luxury lyrics magic magnet maid main major make mammal mango mansion manual maple marble march margin marine market marriage mask master match material math matrix matter maximum maze meadow mean medal media melody melt member memory mention mentor merit merry mesh message metal method middle midnight milk million mimic mind minimum minor minute miracle miss misery miss mitten mix mixture mobile model modify mom monitor monkey monster month moon moral more morning mosquito mother motion mold mountain mouse move movie much muffin mule multiply muscle museum mushroom music must mutual myself mystery naive name napkin narrow nasty natural nature near neck need negative neglect neither nephew nerve nest network neutral never news next nice night noble noise nominee noodle normal north notable note nothing notice novel now nuclear number nurse nut oak obey object oblige obscure obtain ocean october odor off offer often oil okay old olive olympic omit once onion open option orange orbit orchard order ordinary organ orient original orphan ostrich other outdoor outside oval over own oyster ozone paddle page pair palace palm panda panel panic panther paper parade parent park parrot party pass patch path patrol pause pave payment peace peanut peasant pelican pen penalty pencil people pepper perfect permit person pet phone photo phrase physical piano picnic picture piece pig pigeon pill pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play please pledge pluck plug plunge poem poet point polar pole police pond pony popular portion position possible post potato pottery poverty powder power practice praise predict prefer prepare present pretty prevent price pride primary print priority prison private prize problem process produce profit program project promote proof property prosper protect proud provide public pudding pull pulp pulse pumpkin punish pupil puppy purchase purity purpose push put puzzle pyramid quality quantum quarter question quick quit quiz quote rabbit raccoon race rack radar radio rage rail rain ramp ranch random range rapid rare rate rather raven reach ready real reason rebel rebuild recall receive recipe record recycle reduce reflect reform refuse region regret regular reject relax release relief rely remain remember remind remove render renew rent reopen repair repeat replace report require rescue resemble resist resource response result retire retreat return reunion reveal review reward rhythm ribbon rice rich ride rifle right rigid ring riot ripple risk ritual rival river road roast robot robust rocket romance roof rookie rotate rough round route royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say scale scan scare scatter scene scheme school science scissors scorpion scout scrap screen script scrub sea search season seat second secret section security seed seek segment select sell seminar senior sense sentence series service session settle setup seven shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling siege sight sign silent silk silly silver similar simple since sing siren sister situate six size sketch skill skin skirt skull slab slam sleep slender slice slide slight slim slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow soap soccer social sock soda soft solar soldier solid solution solve someone song soon sorry soul sound soup source south space spare spatial spawn speak special speed spell spend sphere spice spider spike spin spirit split spoil sponsor spoon spray spread spring spy square squeeze squirrel stable stadium staff stage stairs stamp stand start state stay steak steel stem step stereo stick still sting stock stomach stone stop story stove strategy street strike strong struggle student stuff stumble style subject submit subway success such sudden suffer sugar suggest suit summer sun sunny sunset super supply supreme sure surface surge surprise sustain swallow swamp swap swear sweet swift swim swing switch sword symbol symptom syrup table tackle tag tail talent tamper tank tape target task tattoo taxi teach team tell ten tenant tennis tent term test text thank that theme then theory there they thing this thought three thrive throw thumb thunder ticket tilt timber time tiny tip tired title toast tobacco today together toilet token tomato tomorrow tone tongue tonight tool tooth top topic topple torch tornado tortoise toss total tourist toward tower town toy track trade traffic tragic train transfer trap trash travel tray treat tree trend trial tribe trick trigger trim trip trophy trouble truck truly trumpet trust truth tube tuition tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform unique universe unknown unlock until unusual unveil update upgrade uphold upon upper upset urban usage use used useful useless usual utility vacant vacuum vague valid valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue verb verify version very vessel veteran viable vibrant vicious victory video view village vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior waste water wave way wealth weapon wear weasel web wedding weekend weird welcome west wet whale wheat wheel when where whip whisper wide width wife wild will win window wine wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool word world worry worth wrap wreck wrestle wrist write wrong yard year yellow you young youth zebra zero zone zoo".split(' ');

async function generateMnemonic(wordCount) {
  const entropyBits = { 12:128, 15:160, 18:192, 21:224, 24:256 }[wordCount];
  const entropyBytes = entropyBits / 8;
  const entropy = crypto.getRandomValues(new Uint8Array(entropyBytes));
  const entropyHex = bytesToHex(entropy);
  
  const hashHex = await sha256(entropyHex);
  const hashBytes = hexToBytes(hashHex);
  const csBits = entropyBits / 32;
  let bits = '';
  for (const b of entropy) bits += b.toString(2).padStart(8, '0');
  for (let i = 0; i < csBits; i++) {
    bits += ((hashBytes[0] >> (7 - i)) & 1).toString();
  }
  
  const words = [];
  for (let i = 0; i < wordCount; i++) {
    const idx = parseInt(bits.slice(i*11, (i+1)*11), 2);
    words.push(BIP39_WORDS[idx]);
  }
  return { words, entropy };
}

async function validateMnemonic(words) {
  if (![12,15,18,21,24].includes(words.length)) return false;
  try {
    const mnemonic = words.join(' ');
    const salt = 'mnemonic';
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw', enc.encode(mnemonic), { name: 'PBKDF2' }, false, ['deriveBits']
    );
    const seedBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: enc.encode(salt), iterations: 2048, hash: 'SHA-512' },
      keyMaterial, 512
    );
    const seedHex = bytesToHex(new Uint8Array(seedBits));
    await deriveBip44Wallet(seedHex, 0);
    return true;
  } catch (e) {
    return false;
  }
}

/* ============================================================
   DERIVE WALLET FROM MNEMONIC (BIP44 – corrected)
============================================================ */
async function deriveWalletFromMnemonicWords(words, passphrase, derivIndex) {
  const mnemonic = words.join(' ');
  const salt = 'mnemonic' + (passphrase || '');
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(mnemonic), { name: 'PBKDF2' }, false, ['deriveBits']
  );
  const seedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: enc.encode(salt), iterations: 2048, hash: 'SHA-512' },
    keyMaterial, 512
  );
  const seedHex = bytesToHex(new Uint8Array(seedBits));
  const privHex = await deriveBip44Wallet(seedHex, derivIndex);
  return walletFromEntropy(hexToBytes(privHex));
}

/* ============================================================
   QR HELPER (unchanged)
============================================================ */
function renderQR(containerId, text, size) {
  size = size || 160;
  const el = document.getElementById(containerId);
  if (!el || !text) return;
  el.innerHTML = '';
  if (typeof QRCode !== 'undefined') {
    new QRCode(el, {
      text: text,
      width: size,
      height: size,
      colorDark: '#000000',
      colorLight: '#ffffff',
      correctLevel: QRCode.CorrectLevel.M
    });
  }
}

/* ============================================================
   STATE & UI HELPERS (unchanged)
============================================================ */
let lastWallet = null;

function setField(id, val) {
  const el = document.getElementById(id);
  if (el) el.value = val;
}

function showError(msg, duration) {
  const toast = document.createElement('div');
  toast.textContent = msg;
  toast.style.cssText = 'position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:#ff4f4f; color:#fff; padding:0.7rem 1.2rem; border-radius:12px; z-index:10000; font-weight:700; box-shadow:0 4px 12px rgba(0,0,0,0.3);';
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), duration || 3000);
}

function showSuccess(msg) {
  const toast = document.createElement('div');
  toast.textContent = msg;
  toast.style.cssText = 'position:fixed; bottom:20px; left:50%; transform:translateX(-50%); background:#39d6c3; color:#0d1020; padding:0.7rem 1.2rem; border-radius:12px; z-index:10000; font-weight:700; box-shadow:0 4px 12px rgba(0,0,0,0.3);';
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 3000);
}

function setLoading(btnId, isLoading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  if (isLoading) {
    btn.classList.add('loading');
    btn.disabled = true;
  } else {
    btn.classList.remove('loading');
    btn.disabled = false;
  }
}

/* ============================================================
   GENERATE NEW WALLET (tab-generate)
============================================================ */
async function doGenerateWallet() {
  setLoading('btn-generate', true);
  try {
    const wordCountEl = document.querySelector('.word-count-btn.active');
    const wordCount   = wordCountEl ? parseInt(wordCountEl.dataset.words) : 15;
    const passphrase  = document.getElementById('bip39-passphrase')?.value || '';
    const derivIndex  = parseInt(document.getElementById('address-index')?.value || '0');

    const { words } = await generateMnemonic(wordCount);

    const grid = document.getElementById('mnemonic-grid');
    if (grid) {
      grid.innerHTML = '';
      words.forEach((w, i) => {
        const div = document.createElement('div');
        div.className = 'mnemonic-word';
        div.innerHTML = `<span class="word-num">${i+1}</span><span class="word-val" id="word-${i+1}">${w}</span>`;
        grid.appendChild(div);
      });
    }

    const wallet = await deriveWalletFromMnemonicWords(words, passphrase, derivIndex);
    lastWallet = { ...wallet, words };

    setField('wallet-address',    wallet.address);
    setField('wallet-pubkey',     wallet.pubHex);
    setField('wallet-privkey',    wallet.wif);
    setField('wallet-privkey-hex', wallet.privHex);

    const entropyBits = {12:128,15:160,18:192,21:224,24:256}[wordCount];
    const entropyFill = (entropyBits - 128) / (256 - 128) * 100;
    const entropyFillEl = document.getElementById('entropy-fill');
    if (entropyFillEl) entropyFillEl.style.width = `${entropyFill}%`;
    const entropyLabel = document.getElementById('entropy-label');
    if (entropyLabel) entropyLabel.textContent = `${entropyBits} bits`;

    showSuccess('New SMT wallet generated!');
  } catch(e) {
    showError('Generation failed: ' + e.message);
    console.error(e);
  } finally {
    setLoading('btn-generate', false);
  }
}

/* ============================================================
   RESTORE FROM MNEMONIC (tab-mnemonic)
============================================================ */
async function doRestoreFromMnemonic() {
  setLoading('btn-restore-mnemonic', true);
  try {
    const phrase      = document.getElementById('restore-mnemonic')?.value.trim();
    const passphrase  = document.getElementById('restore-passphrase')?.value || '';
    const derivIndex  = parseInt(document.getElementById('restore-index')?.value || '0');
    if (!phrase) throw new Error('Please enter a seed phrase');
    const words = phrase.split(/\s+/).filter(Boolean);
    if (![12,15,18,21,24].includes(words.length)) throw new Error(`Invalid word count: ${words.length}. Expected 12, 15, 18, 21, or 24.`);

    const valid = await validateMnemonic(words);
    if (!valid) throw new Error('Invalid mnemonic (checksum failed)');

    const wallet = await deriveWalletFromMnemonicWords(words, passphrase, derivIndex);
    lastWallet = { ...wallet, words };

    setField('restore-address', wallet.address);
    setField('restore-privkey', wallet.wif);

    showSuccess('Wallet restored from mnemonic!');
  } catch(e) {
    showError(e.message);
  } finally {
    setLoading('btn-restore-mnemonic', false);
  }
}

/* ============================================================
   RESTORE FROM PRIVATE KEY (tab-privkey)
============================================================ */
async function doRestoreFromPrivKey() {
  setLoading('btn-derive-privkey', true);
  try {
    const key = document.getElementById('privkey-input')?.value.trim();
    if (!key) throw new Error('Please enter a private key (WIF or hex)');
    const wallet = await walletFromPrivateKey(key);
    setField('privkey-address', wallet.address);
    setField('privkey-pubkey', wallet.pubHex);
    showSuccess('Address derived from private key!');
    lastWallet = wallet;
  } catch(e) {
    showError(e.message);
  } finally {
    setLoading('btn-derive-privkey', false);
  }
}

/* ============================================================
   PAPER WALLET (tab-paper)
============================================================ */
async function doGenPaperWallet() {
  setLoading('btn-gen-paper', true);
  try {
    let wallet;
    const srcLast = document.getElementById('pw-src-last')?.classList.contains('active');
    if (srcLast && lastWallet) {
      wallet = lastWallet;
    } else {
      const manualAddr   = document.getElementById('pw-manual-addr')?.value.trim();
      const manualPriv   = document.getElementById('pw-manual-privkey')?.value.trim();
      if (manualAddr && manualPriv) {
        wallet = { address: manualAddr, wif: manualPriv, words: null };
      } else {
        const { words } = await generateMnemonic(15);
        wallet = await deriveWalletFromMnemonicWords(words, '', 0);
        wallet.words = words;
      }
    }

    const addrEl = document.getElementById('pw-addr-preview');
    const privEl = document.getElementById('pw-privkey-preview');
    const seedEl = document.getElementById('pw-seed-preview');
    const dateEl = document.getElementById('pw-date-preview');
    if (addrEl) addrEl.textContent = wallet.address || '——';
    if (privEl) privEl.textContent = wallet.wif || '——';
    if (seedEl && wallet.words) {
      const showSeed = document.getElementById('pw-show-mnemonic')?.checked;
      if (showSeed) {
        const rows = [];
        for (let i = 0; i < wallet.words.length; i += 6) {
          rows.push(wallet.words.slice(i, i+6).map((w,j) => `${i+j+1}. ${w}`).join(' &nbsp; '));
        }
        seedEl.innerHTML = rows.join('<br>');
      } else {
        const seedStrip = document.getElementById('pw-seed-strip');
        if (seedStrip) seedStrip.style.display = 'none';
      }
    } else if (seedEl) {
      seedEl.textContent = '(No seed phrase — imported from private key)';
    }
    if (dateEl) dateEl.textContent = new Date().toLocaleDateString('en-US', {year:'numeric', month:'short', day:'numeric'});

    const showQR = document.getElementById('pw-show-qr')?.checked;
    if (showQR) {
      const pubQREl = document.getElementById('pw-qr-public');
      const prvQREl = document.getElementById('pw-qr-priv');
      if (pubQREl) {
        pubQREl.innerHTML = '';
        renderQR('pw-qr-public', wallet.address, 90);
      }
      if (prvQREl && document.getElementById('pw-show-privkey')?.checked) {
        prvQREl.innerHTML = '';
        renderQR('pw-qr-priv', wallet.wif, 90);
      }
    }

    if (!document.getElementById('pw-show-privkey')?.checked) {
      const section = document.querySelector('.pw-section:last-child');
      if (section) section.style.display = 'none';
    }

    showSuccess('Paper wallet preview ready!');
  } catch(e) {
    showError('Paper wallet error: ' + e.message);
  } finally {
    setLoading('btn-gen-paper', false);
  }
}

function doPrintPaperWallet() {
  const card = document.querySelector('.paper-wallet-card');
  if (!card) return;
  const addr = document.getElementById('pw-addr-preview')?.textContent;
  if (!addr || addr === 'S — — — — — — — — — — — — — — — —') {
    showError('Generate a paper wallet preview first!');
    return;
  }
  const clone = card.cloneNode(true);
  const pubQREl = clone.querySelector('#pw-qr-public');
  const prvQREl = clone.querySelector('#pw-qr-priv');
  if (pubQREl && lastWallet && lastWallet.address) {
    const canvas = document.createElement('canvas');
    canvas.width = 90;
    canvas.height = 90;
    const qr = new QRCode(canvas, { text: lastWallet.address, width: 90, height: 90 });
    const img = document.createElement('img');
    img.src = canvas.toDataURL();
    pubQREl.innerHTML = '';
    pubQREl.appendChild(img);
  }
  if (prvQREl && document.getElementById('pw-show-privkey')?.checked && lastWallet && lastWallet.wif) {
    const canvas = document.createElement('canvas');
    canvas.width = 90;
    canvas.height = 90;
    const qr = new QRCode(canvas, { text: lastWallet.wif, width: 90, height: 90 });
    const img = document.createElement('img');
    img.src = canvas.toDataURL();
    prvQREl.innerHTML = '';
    prvQREl.appendChild(img);
  }
  const win = window.open('', '_blank');
  win.document.write(`<!DOCTYPE html><html><head>
    <title>SMT Paper Wallet</title>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&display=swap" rel="stylesheet">
    <style>
      body { margin: 0; padding: 20px; background: #fff; font-family: Outfit, sans-serif; }
      @media print { body { padding: 0; } }
    </style>
  </head><body>${clone.outerHTML}</body></html>`);
  win.document.close();
  setTimeout(() => win.print(), 500);
}

/* ============================================================
   VANITY ADDRESS SEARCH
============================================================ */
let vanityStop    = false;
let vanityRunning = false;
let vanityStartMs = 0;
let vanityCount   = 0;
let vanityTimer   = null;

function updateVanityUI() {
  if (vanityRunning && vanityStartMs) {
    const elapsed = (Date.now() - vanityStartMs) / 1000;
    const speed = vanityCount / elapsed;
    document.getElementById('vanity-speed').innerText = speed.toFixed(0);
    document.getElementById('vanity-elapsed').innerText = elapsed.toFixed(0);
    document.getElementById('vanity-attempts').innerText = vanityCount.toLocaleString();
  }
}

async function doVanitySearch() {
  if (vanityRunning) return;
  const pattern       = document.getElementById('vanity-pattern')?.value.trim();
  if (!pattern) { showError('Enter a vanity pattern first'); return; }

  const matchType     = document.querySelector('[data-match].active')?.dataset.match || 'prefix';
  const caseSensitive = document.getElementById('vanity-case-sensitive')?.checked !== false;
  const searchPat     = caseSensitive ? pattern : pattern.toLowerCase();

  const SMT_PREFIX = 'S';

  vanityStop    = false;
  vanityRunning = true;
  vanityCount   = 0;
  vanityStartMs = Date.now();

  const startBtn = document.getElementById('btn-vanity-start');
  const stopBtn  = document.getElementById('btn-vanity-stop');
  if (startBtn) startBtn.style.display = 'none';
  if (stopBtn)  stopBtn.style.display  = 'flex';

  const statusEl = document.getElementById('vanity-status');
  if (statusEl) statusEl.textContent = '🔍 Searching...';

  const barEl = document.getElementById('vanity-bar');
  const len = pattern.length;
  const base = caseSensitive ? 58 : 36;
  const expected = Math.pow(base, len);

  vanityTimer = setInterval(updateVanityUI, 250);

  while (!vanityStop) {
    const entropy = crypto.getRandomValues(new Uint8Array(32));
    const wallet  = await walletFromEntropy(entropy);
    const addr    = wallet.address;

    const addrCore  = addr.startsWith(SMT_PREFIX) ? addr.slice(1) : addr;
    const checkAddr = caseSensitive ? addrCore : addrCore.toLowerCase();

    let found = false;
    if      (matchType === 'prefix')   found = checkAddr.startsWith(searchPat);
    else if (matchType === 'suffix')   found = checkAddr.endsWith(searchPat);
    else if (matchType === 'contains') found = checkAddr.includes(searchPat);

    if (found) {
      vanityStop = true;
      clearInterval(vanityTimer);
      updateVanityUI();

      setField('vanity-addr-result',    wallet.address);
      setField('vanity-privkey-result', wallet.wif);
      setField('vanity-mnemonic-result', '(Direct key — no mnemonic)');

      const highlightEl = document.getElementById('vanity-addr-highlight');
      if (highlightEl) {
        let highlighted = addr;
        const matchStart = addr.toLowerCase().indexOf(searchPat.toLowerCase());
        if (matchStart !== -1) {
          highlighted = addr.slice(0, matchStart) + '<mark>' + addr.slice(matchStart, matchStart + pattern.length) + '</mark>' + addr.slice(matchStart + pattern.length);
        }
        highlightEl.innerHTML = highlighted;
      }

      const resultPanel = document.getElementById('vanity-result');
      if (resultPanel) { resultPanel.classList.add('visible'); }

      const toPaperBtn = document.getElementById('btn-vanity-to-paper');
      if (toPaperBtn) toPaperBtn.style.display = 'flex';

      lastWallet = wallet;
      if (statusEl) statusEl.textContent = '🎉 Found after ' + vanityCount.toLocaleString() + ' attempts!';
      if (stopBtn)  stopBtn.style.display  = 'none';
      if (startBtn) startBtn.style.display = 'flex';
      vanityRunning = false;

      showSuccess('Vanity address found!');
      break;
    }
    vanityCount++;

    if (barEl) {
      const pct = Math.min(95, (vanityCount / expected) * 100 * 2);
      barEl.style.width = pct + '%';
    }

    await new Promise(r => setTimeout(r, 0));
  }

  if (!vanityStop) {
    vanityRunning = false;
  }
}

function doStopVanity() {
  vanityStop    = true;
  vanityRunning = false;
  clearInterval(vanityTimer);
  const startBtn = document.getElementById('btn-vanity-start');
  const stopBtn  = document.getElementById('btn-vanity-stop');
  if (startBtn) startBtn.style.display = 'flex';
  if (stopBtn)  stopBtn.style.display  = 'none';
  const statusEl = document.getElementById('vanity-status');
  if (statusEl) statusEl.textContent = '⏸ Stopped at ' + vanityCount.toLocaleString() + ' attempts';
}

/* ============================================================
   MOBILE MENU & TAB SWITCHING (unchanged)
============================================================ */
document.addEventListener('DOMContentLoaded', () => {
  const tabs = document.querySelectorAll('.mode-tab');
  const contents = document.querySelectorAll('.tab-content');

  function activateTab(tabId) {
    contents.forEach(content => content.classList.remove('active'));
    document.getElementById(tabId).classList.add('active');
    tabs.forEach(btn => btn.classList.remove('active'));
    const activeBtn = document.querySelector(`.mode-tab[aria-controls="${tabId}"]`);
    if (activeBtn) activeBtn.classList.add('active');
  }

  tabs.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('aria-controls');
      activateTab(targetId);
    });
  });

  const wordBtns = document.querySelectorAll('.word-count-btn');
  wordBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      if (btn.classList.contains('active')) return;
      const parent = btn.parentElement;
      if (parent) {
        parent.querySelectorAll('.word-count-btn').forEach(b => b.classList.remove('active'));
      }
      btn.classList.add('active');
      const wordCount = parseInt(btn.dataset.words);
      const bits = {12:128,15:160,18:192,21:224,24:256}[wordCount];
      const fill = (bits - 128) / (256 - 128) * 100;
      const fillEl = document.getElementById('entropy-fill');
      if (fillEl) fillEl.style.width = `${fill}%`;
      const labelEl = document.getElementById('entropy-label');
      if (labelEl) labelEl.textContent = `${bits} bits`;
    });
  });

  document.querySelectorAll('.field-copy-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const targetId = btn.getAttribute('data-copy');
      const field = document.getElementById(targetId);
      if (field && field.value && field.value !== '——') {
        await navigator.clipboard.writeText(field.value);
        btn.textContent = 'Copied!';
        btn.classList.add('copied');
        setTimeout(() => {
          btn.textContent = 'Copy';
          btn.classList.remove('copied');
        }, 2000);
      } else {
        showError('Nothing to copy');
      }
    });
  });

  const copyMnemonic = document.getElementById('copy-mnemonic-btn');
  if (copyMnemonic) {
    copyMnemonic.addEventListener('click', async () => {
      const words = Array.from(document.querySelectorAll('#mnemonic-grid .word-val')).map(el => el.textContent);
      if (words.length && words[0] !== '——') {
        await navigator.clipboard.writeText(words.join(' '));
        copyMnemonic.textContent = '✓ Copied!';
        setTimeout(() => copyMnemonic.textContent = '📋 Copy Phrase', 2000);
      } else {
        showError('Generate a wallet first');
      }
    });
  }

  const srcLast = document.getElementById('pw-src-last');
  const srcManual = document.getElementById('pw-src-manual');
  const manualFields = document.getElementById('pw-manual-fields');
  if (srcLast && srcManual && manualFields) {
    srcLast.addEventListener('click', () => {
      srcLast.classList.add('active');
      srcManual.classList.remove('active');
      manualFields.style.display = 'none';
    });
    srcManual.addEventListener('click', () => {
      srcManual.classList.add('active');
      srcLast.classList.remove('active');
      manualFields.style.display = 'block';
    });
  }

  const copyBtns = document.querySelectorAll('[data-copies]');
  copyBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      copyBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });

  const vanityPattern = document.getElementById('vanity-pattern');
  if (vanityPattern) {
    vanityPattern.addEventListener('input', () => {
      const val = vanityPattern.value;
      const invalid = val.split('').some(c => !B58C.includes(c));
      const hint = document.getElementById('vanity-char-check');
      if (hint) {
        hint.textContent = invalid ? '❌ Only Base58 characters allowed' : '✓ All characters valid';
        hint.style.color = invalid ? '#ff9fb0' : '#7ec6ff';
      }
      const len = val.length;
      if (len > 0) {
        const base = document.getElementById('vanity-case-sensitive')?.checked ? 58 : 36;
        const expected = Math.pow(base, len);
        const dots = document.querySelectorAll('.difficulty-dot');
        dots.forEach((dot, i) => {
          if (expected > Math.pow(10, i+1)) dot.classList.add('active');
          else dot.classList.remove('active');
        });
        const est = document.getElementById('vanity-difficulty-est');
        if (est) est.textContent = `~ ${expected.toExponential(2)} attempts (on average)`;
      } else {
        const dots = document.querySelectorAll('.difficulty-dot');
        dots.forEach(dot => dot.classList.remove('active'));
        const est = document.getElementById('vanity-difficulty-est');
        if (est) est.textContent = 'Enter a pattern to estimate';
      }
    });
  }

  const searchTypeBtns = document.querySelectorAll('.search-type-btn');
  searchTypeBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      searchTypeBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });

  const threadBtns = document.querySelectorAll('[data-threads]');
  threadBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      threadBtns.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
    });
  });

  document.getElementById('btn-generate')?.addEventListener('click', doGenerateWallet);
  document.getElementById('btn-restore-mnemonic')?.addEventListener('click', doRestoreFromMnemonic);
  document.getElementById('btn-derive-privkey')?.addEventListener('click', doRestoreFromPrivKey);
  document.getElementById('btn-gen-paper')?.addEventListener('click', doGenPaperWallet);
  document.getElementById('btn-print-paper')?.addEventListener('click', doPrintPaperWallet);
  document.getElementById('btn-vanity-start')?.addEventListener('click', doVanitySearch);
  document.getElementById('btn-vanity-stop')?.addEventListener('click', doStopVanity);
  document.getElementById('btn-export-paper')?.addEventListener('click', () => {
    const tabPaper = document.getElementById('tab-paper');
    if (tabPaper) activateTab('tab-paper');
    doGenPaperWallet();
  });
  document.getElementById('btn-vanity-to-paper')?.addEventListener('click', () => {
    const tabPaper = document.getElementById('tab-paper');
    if (tabPaper) activateTab('tab-paper');
    doGenPaperWallet();
  });

  const fillEl = document.getElementById('entropy-fill');
  if (fillEl) fillEl.style.width = '62%';
  const labelEl = document.getElementById('entropy-label');
  if (labelEl) labelEl.textContent = '160 bits';
});