'use strict';
/* ============================================================
   DORKCOIN — NETWORK PARAMETERS (VERIFIED via on-chain decode)
   ============================================================
   pubkey_address = 0x1e (30)  → D...        Legacy P2PKH (BIP44)
   script_address = 0x08  (8)  → 4...        SegWit P2SH  (BIP49)
   secret_key     = 0x9e (158) → Q...        WIF compressed (all types)
   segwit_hrp     = "dorkcoin" → dorkcoin1.. Native SegWit mainnet (BIP84)
   segwit_hrp_t   = "dorktest" → dorktest1.. Native SegWit testnet (BIP84)
   taproot_hrp    = "dork"     → dork1...    Taproot mainnet (BIP86)
   coin_type      = 4151811    SLIP-44
   ============================================================ */
const DORK_PUBKEY_VERSION = 0x1e;
const DORK_WIF_VERSION    = 0x9e;
const USE_COMPRESSED      = true;

/* ── secp256k1 (existing, used by Generate/Recover/Vanity/Paper tabs) ─────── */
const P_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;

function modInv(a, m) {
  let old_r = ((a % m) + m) % m, r = m, old_s = 1n, s = 0n;
  while (r !== 0n) { let q = old_r / r; [old_r,r]=[r,old_r-q*r]; [old_s,s]=[s,old_s-q*s]; }
  return ((old_s % m) + m) % m;
}
function ecAdd(p1, p2) {
  if (!p1) return p2; if (!p2) return p1;
  const [x1,y1]=p1, [x2,y2]=p2; let lam;
  if (x1===x2) { if((y1+y2)%P_CURVE===0n)return null; lam=(3n*x1*x1)*modInv(2n*y1,P_CURVE)%P_CURVE; }
  else { lam=((y2-y1)%P_CURVE+P_CURVE)%P_CURVE*modInv((x2-x1+P_CURVE)%P_CURVE,P_CURVE)%P_CURVE; }
  const x3=(lam*lam-x1-x2)%P_CURVE, y3=(lam*(x1-x3)-y1)%P_CURVE;
  return [(x3+P_CURVE)%P_CURVE,(y3+P_CURVE)%P_CURVE];
}
function ecMul(k, p) {
  let r=null, add=p; k=((k%N_CURVE)+N_CURVE)%N_CURVE;
  while(k>0n){if(k&1n)r=ecAdd(r,add);add=ecAdd(add,add);k>>=1n;} return r;
}
function pubkeyCompressed(privHex) {
  const k=BigInt('0x'+privHex), pt=ecMul(k,[Gx,Gy]);
  return ((pt[1]%2n===0n)?'02':'03')+pt[0].toString(16).padStart(64,'0');
}
function pubkeyUncompressed(privHex) {
  const k=BigInt('0x'+privHex), pt=ecMul(k,[Gx,Gy]);
  return '04'+pt[0].toString(16).padStart(64,'0')+pt[1].toString(16).padStart(64,'0');
}
async function sha256hex(dataHex) {
  const hash=await crypto.subtle.digest('SHA-256',hexToBytes(dataHex));
  return bytesToHex(new Uint8Array(hash));
}
async function dblSha256(dataHex){return sha256hex(await sha256hex(dataHex));}

const B58C='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58encode(bytes){
  let n=BigInt('0x'+bytesToHex(bytes)),res='';
  while(n>0n){const r=n%58n;n/=58n;res=B58C[Number(r)]+res;}
  for(let i=0;i<bytes.length&&bytes[i]===0;i++)res='1'+res; return res;
}
async function b58checkEncode(payloadHex){
  const chk=(await dblSha256(payloadHex)).slice(0,8);
  return b58encode(hexToBytes(payloadHex+chk));
}
async function privToWIF(privHex){
  return b58checkEncode(DORK_WIF_VERSION.toString(16).padStart(2,'0')+privHex+(USE_COMPRESSED?'01':''));
}
async function pubkeyToAddress(pubHex){
  const sha=await sha256hex(pubHex);
  const ripe=ripemd160CryptoJS(hexToBytes(sha));
  return b58checkEncode(DORK_PUBKEY_VERSION.toString(16).padStart(2,'0')+bytesToHex(ripe));
}
function ripemd160CryptoJS(msg){
  const h=CryptoJS.RIPEMD160(CryptoJS.lib.WordArray.create(msg)),r=new Uint8Array(20);
  for(let i=0;i<20;i++)r[i]=(h.words[i>>>2]>>>(24-(i%4)*8))&0xff; return r;
}
function hexToBytes(hex){const b=new Uint8Array(hex.length/2);for(let i=0;i<hex.length;i+=2)b[i/2]=parseInt(hex.slice(i,i+2),16);return b;}
function bytesToHex(b){return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');}

/* ── QR helpers ── */
function renderQR(canvasId,text){
  const c=document.getElementById(canvasId);if(!c||!text)return;
  c.width=c.height=180;const ctx=c.getContext('2d');ctx.clearRect(0,0,180,180);
  try{if(typeof QRCode!=='undefined')new QRCode(c,{text,width:180,height:180,colorDark:'#000',colorLight:'#fff',correctLevel:QRCode.CorrectLevel.M});}
  catch(e){ctx.fillStyle='#f8f9fa';ctx.fillRect(0,0,180,180);ctx.fillStyle='#666';ctx.font='11px monospace';ctx.textAlign='center';ctx.fillText('QR unavailable',90,90);}
}
function renderQRDiv(containerId,text){
  const c=document.getElementById(containerId);if(!c||!text)return;
  c.innerHTML='';
  if(typeof QRCode!=='undefined')new QRCode(c,{text,width:180,height:180,colorDark:'#000',colorLight:'#fff',correctLevel:QRCode.CorrectLevel.M});
}

/* ── walletFromEntropy / walletFromPrivateKey (used by Generate/Vanity/Paper) ── */
async function walletFromEntropy(entropy){
  const privHex=bytesToHex(entropy), pubHex=USE_COMPRESSED?pubkeyCompressed(privHex):pubkeyUncompressed(privHex);
  return{privHex,pubHex,address:await pubkeyToAddress(pubHex),wif:await privToWIF(privHex)};
}
async function walletFromPrivateKey(wif){
  const decoded=(()=>{
    const bytes=(()=>{let n=0n;for(let c of wif){const i=B58C.indexOf(c);if(i===-1)throw new Error('Invalid base58 char');n=n*58n+BigInt(i);}
      const b=[];while(n>0n){b.unshift(Number(n&0xFFn));n>>=8n;}return new Uint8Array(b);})();
    let l=0;while(l<wif.length&&wif[l]==='1')l++;
    const r=new Uint8Array(bytes.length+l);r.set(bytes,l);return r;
  })();
  const checksum=decoded.slice(-4),payload=decoded.slice(0,-4);
  if(bytesToHex(checksum)!==(await dblSha256(bytesToHex(payload))).slice(0,8))throw new Error('Invalid WIF checksum');
  if(payload[0]!==DORK_WIF_VERSION)throw new Error(`Invalid version byte: expected ${DORK_WIF_VERSION}, got ${payload[0]}`);
  const privHex=bytesToHex(payload.slice(1,33)),hasComp=payload.length===34&&payload[33]===0x01;
  const pubHex=hasComp?pubkeyCompressed(privHex):pubkeyUncompressed(privHex);
  return{privHex,pubHex,address:await pubkeyToAddress(pubHex),wif:await privToWIF(privHex),compressed:hasComp};
}

/* ── UI helpers (used by existing tabs) ── */
function copyEl(id){const el=document.getElementById(id);if(el)navigator.clipboard.writeText(el.innerText);}
function hideErr(id){const e=document.getElementById(id);if(e)e.classList.remove('show');}
function switchTab(tab,btn){
  if(typeof bootstrap!=='undefined'&&bootstrap.Tab){new bootstrap.Tab(btn).show();}
  else{
    document.querySelectorAll('.tab-pane').forEach(t=>t.classList.remove('show','active'));
    const target=document.getElementById(tab+'-tab');if(target)target.classList.add('show','active');
    document.querySelectorAll('.nav-link').forEach(b=>b.classList.remove('active'));
    if(btn)btn.classList.add('active');
  }
}

/* ── Generate tab ── */
let lastGeneratedWallet=null;
async function generateWallet(){
  const w=await walletFromEntropy(crypto.getRandomValues(new Uint8Array(32)));
  lastGeneratedWallet=w;
  document.getElementById('address-display').innerText=w.address;
  document.getElementById('seed-display').innerText=w.wif;
  document.getElementById('public-key-display').innerText=w.pubHex;
  document.getElementById('generated-wallet').style.display='block';
  setTimeout(()=>{renderQRDiv('gen-address-qr',w.address);renderQRDiv('gen-privkey-qr',w.wif);},50);
}

/* ── Recover tab ── */
async function recoverFromWif(){
  const wif=document.getElementById('recovery-wif').value.trim();
  const errDiv=document.getElementById('wif-error');
  try{
    const w=await walletFromPrivateKey(wif);
    document.getElementById('recovered-address').innerText=w.address;
    document.getElementById('recovered-seed').innerText=w.wif;
    document.getElementById('recovered-public-key').innerText=w.pubHex;
    const s=document.getElementById('recovery-checksum-status');
    s.innerText=`✓ Wallet recovered (${w.compressed?'compressed':'uncompressed'})`;
    s.className='checksum-status cs-ok';s.style.display='block';
    document.getElementById('recovered-wallet').style.display='block';
    errDiv.classList.remove('show');
    setTimeout(()=>{renderQRDiv('rec-address-qr',w.address);renderQRDiv('rec-privkey-qr',w.wif);},50);
  }catch(e){errDiv.innerText=e.message;errDiv.classList.add('show');document.getElementById('recovered-wallet').style.display='none';}
}

/* ── Vanity tab ── */
let vanityStop=false,vanityTimeout=null,vanityStartTime=0,vanityAttempts=0,vanityMaxAttempts=0;
function updateVanityStats(){
  const e=(Date.now()-vanityStartTime)/1000,s=vanityAttempts/e;
  document.getElementById('attempts-count').innerText=vanityAttempts.toLocaleString();
  document.getElementById('speed-count').innerText=Math.round(s).toLocaleString();
  document.getElementById('elapsed-time').innerText=e.toFixed(1)+'s';
  document.getElementById('vanity-progress-bar').style.width=Math.min(100,(vanityAttempts/vanityMaxAttempts)*100)+'%';
}
async function startVanitySearch(){
  if(vanityTimeout)return;
  const pattern=document.getElementById('vanity-pattern').value.trim();
  if(!pattern){alert('Please enter a pattern to search.');return;}
  vanityMaxAttempts=parseInt(document.getElementById('max-attempts').value,10);
  const position=document.getElementById('vanity-position').value;
  const caseSensitive=document.getElementById('case-sensitive').value==='true';
  const searchPattern=caseSensitive?pattern:pattern.toLowerCase();
  vanityStop=false;vanityAttempts=0;vanityStartTime=Date.now();
  document.getElementById('vanity-progress').style.display='block';
  document.getElementById('vanity-result').style.display='none';
  const updateInterval=setInterval(()=>updateVanityStats(),200);
  for(let i=0;i<vanityMaxAttempts;i++){
    if(vanityStop)break;
    const wallet=await walletFromEntropy(crypto.getRandomValues(new Uint8Array(32)));
    const checkAddr=caseSensitive?wallet.address:wallet.address.toLowerCase();
    const found=position==='start'?checkAddr.slice(1).startsWith(searchPattern):checkAddr.includes(searchPattern);
    if(found){
      document.getElementById('vanity-address').innerText=wallet.address;
      document.getElementById('vanity-seed').innerText=wallet.wif;
      document.getElementById('vanity-public-key').innerText=wallet.pubHex;
      document.getElementById('vanity-result').style.display='block';
      vanityStop=true;
      setTimeout(()=>{renderQRDiv('vanity-address-qr',wallet.address);renderQRDiv('vanity-privkey-qr',wallet.wif);},50);
      break;
    }
    vanityAttempts++;
    if(i%100===0)await new Promise(r=>setTimeout(r,0));
  }
  clearInterval(updateInterval);vanityTimeout=null;
  document.getElementById('vanity-progress').style.display='none';
  if(!vanityStop)alert('Vanity address not found. Try increasing max trials or a simpler pattern.');
}
function stopVanitySearch(){vanityStop=true;}


/* ============================================================
   BIP39 MODULE
   Full HD wallet: mnemonic → seed → 5 address types
   Runs in IIFE to avoid naming conflicts with existing code above
   ============================================================ */
(async function BIP39_MODULE(){

/* ── Crypto primitives (Uint8Array-based, no CryptoJS dependency) ── */
async function sha256u8(data){
  const b=data instanceof Uint8Array?data:new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest('SHA-256',b));
}
async function hmacSha512(key,data){
  const k=await crypto.subtle.importKey('raw',key,{name:'HMAC',hash:'SHA-512'},false,['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC',k,data));
}
async function pbkdf2Sha512(pass,salt,iter,len){
  const k=await crypto.subtle.importKey('raw',pass,'PBKDF2',false,['deriveBits']);
  const b=await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-512',salt,iterations:iter},k,len*8);
  return new Uint8Array(b);
}

/* ── RIPEMD-160 pure JS ── */
function ripemd160(msg){
  function rl(x,n){return(x<<n)|(x>>>(32-n));}
  function f(j,x,y,z){if(j<16)return x^y^z;if(j<32)return(x&y)|(~x&z);if(j<48)return(x|~y)^z;if(j<64)return(x&z)|(y&~z);return x^(y|~z);}
  const K=[0,0x5a827999,0x6ed9eba1,0x8f1bbcdc,0xa953fd4e];
  const KK=[0x50a28be6,0x5c4dd124,0x6d703ef3,0x7a6d76e9,0];
  const R=[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  const RR=[5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  const S=[11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  const SS=[8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  const m=msg instanceof Uint8Array?msg:new TextEncoder().encode(msg),orig=m.length,bitLen=orig*8;
  const padLen=orig+1+((orig%64<56)?(55-orig%64):(119-orig%64));
  const padded=new Uint8Array(padLen+8);padded.set(m);padded[orig]=0x80;
  const view=new DataView(padded.buffer);
  view.setUint32(padLen,bitLen&0xffffffff,true);view.setUint32(padLen+4,Math.floor(bitLen/4294967296),true);
  let h0=0x67452301,h1=0xefcdab89,h2=0x98badcfe,h3=0x10325476,h4=0xc3d2e1f0;
  const w=new DataView(padded.buffer);
  for(let i=0;i<padded.length;i+=64){
    const X=[];for(let j=0;j<16;j++)X.push(w.getInt32(i+j*4,true));
    let [a,b,c,d,e]=[h0,h1,h2,h3,h4],[aa,bb,cc,dd,ee]=[h0,h1,h2,h3,h4];
    for(let j=0;j<80;j++){
      let T=(rl(a+f(j,b,c,d)+X[R[j]]+K[Math.floor(j/16)],S[j])+e)|0;
      [a,b,c,d,e]=[e,T,b,rl(c,10),d];
      T=(rl(aa+f(79-j,bb,cc,dd)+X[RR[j]]+KK[Math.floor(j/16)],SS[j])+ee)|0;
      [aa,bb,cc,dd,ee]=[ee,T,bb,rl(cc,10),dd];
    }
    const T=(h1+c+dd)|0;h1=(h2+d+ee)|0;h2=(h3+e+aa)|0;h3=(h4+a+bb)|0;h4=(h0+b+cc)|0;h0=T;
  }
  const out=new Uint8Array(20),ov=new DataView(out.buffer);
  [h0,h1,h2,h3,h4].forEach((h,i)=>ov.setInt32(i*4,h,true));return out;
}
async function hash160(data){return ripemd160(await sha256u8(data));}

/* ── Base58Check (Uint8Array) ── */
const B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58enc(buf){
  let n=0n;for(const b of buf)n=n*256n+BigInt(b);
  let s='';while(n>0n){s=B58[Number(n%58n)]+s;n/=58n;}
  for(const b of buf){if(b!==0)break;s='1'+s;}return s;
}
async function bs58check(payload){
  const c1=await sha256u8(payload),c2=await sha256u8(c1);
  const out=new Uint8Array(payload.length+4);out.set(payload);out.set(c2.slice(0,4),payload.length);
  return b58enc(out);
}

/* ── Bech32 / Bech32m ── */
const B32C='qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const B32G=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];
function b32poly(v){let c=1;for(const x of v){const t=c>>25;c=((c&0x1ffffff)<<5)^x;for(let i=0;i<5;i++)if((t>>i)&1)c^=B32G[i];}return c;}
function b32hrp(h){const r=[];for(const c of h)r.push(c.charCodeAt(0)>>5);r.push(0);for(const c of h)r.push(c.charCodeAt(0)&31);return r;}
function cvtbits(data,from,to,pad=true){let acc=0,bits=0;const r=[],m=(1<<to)-1;for(const v of data){acc=(acc<<from)|v;bits+=from;while(bits>=to){bits-=to;r.push((acc>>bits)&m);}}if(pad&&bits>0)r.push((acc<<(to-bits))&m);return r;}
function bech32enc(hrp,wv,prog,m32){
  const data=[wv,...cvtbits([...prog],8,5)];
  const exp=[...b32hrp(hrp),...data,0,0,0,0,0,0];
  const mod=b32poly(exp)^(m32?0x2bc830a3:1);
  const chk=[];for(let i=0;i<6;i++)chk.push((mod>>(5*(5-i)))&31);
  return hrp+'1'+[...data,...chk].map(d=>B32C[d]).join('');
}

/* ── secp256k1 (BigInt) ── */
const P=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn;
const N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;
const GX=0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n;
const GY=0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n;
function invP2(a){let r=1n,b=a,e=P-2n;while(e>0n){if(e&1n)r=r*b%P;e>>=1n;b=b*b%P;}return r;}
function ptAdd(p1,p2){
  if(!p1)return p2;if(!p2)return p1;
  if(p1[0]===p2[0]){if(p1[1]!==p2[1])return null;const m=((3n*p1[0]*p1[0])*invP2(2n*p1[1]))%P;const x=(m*m-2n*p1[0]+2n*P)%P;return[x,(m*(p1[0]-x+P)-p1[1]+P)%P];}
  const m=((p2[1]-p1[1]+P)*invP2(p2[0]-p1[0]+P))%P;const x=(m*m-p1[0]-p2[0]+2n*P)%P;return[x,(m*(p1[0]-x+P)-p1[1]+P)%P];
}
function ptMul(k,pt){let R=null,Q=pt;while(k>0n){if(k&1n)R=ptAdd(R,Q);Q=ptAdd(Q,Q);k>>=1n;}return R;}
function privToPub(privBytes){
  const k=BigInt('0x'+[...privBytes].map(b=>b.toString(16).padStart(2,'0')).join(''));
  const [x,y]=ptMul(k,[GX,GY]);
  const pub=new Uint8Array(33);pub[0]=(y&1n)===0n?0x02:0x03;
  const xh=x.toString(16).padStart(64,'0');for(let i=0;i<32;i++)pub[i+1]=parseInt(xh.slice(i*2,i*2+2),16);
  return pub;
}

/* ── BIP32 HD ── */
async function seedToMaster(seed){
  const I=await hmacSha512(new TextEncoder().encode('Bitcoin seed'),seed);
  return{key:I.slice(0,32),chain:I.slice(32)};
}
async function deriveChild(parent,index,hardened){
  const i=hardened?(index+0x80000000)>>>0:index;
  const ib=new Uint8Array(4);new DataView(ib.buffer).setUint32(0,i,false);
  let data;
  if(hardened){data=new Uint8Array(37);data[0]=0x00;data.set(parent.key,1);data.set(ib,33);}
  else{const pub=privToPub(parent.key);data=new Uint8Array(37);data.set(pub,0);data.set(ib,33);}
  const I=await hmacSha512(parent.chain,data);
  const IL=I.slice(0,32),IR=I.slice(32);
  const ILn=BigInt('0x'+[...IL].map(b=>b.toString(16).padStart(2,'0')).join(''));
  const pkn=BigInt('0x'+[...parent.key].map(b=>b.toString(16).padStart(2,'0')).join(''));
  const cn=((ILn+pkn)%N+N)%N;
  const hex=cn.toString(16).padStart(64,'0');
  const childKey=new Uint8Array(32);for(let i=0;i<32;i++)childKey[i]=parseInt(hex.slice(i*2,i*2+2),16);
  return{key:childKey,chain:IR};
}
async function derivePath(seed,pathStr){
  let node=await seedToMaster(seed);
  for(const part of pathStr.split('/').slice(1)){const h=part.endsWith("'");node=await deriveChild(node,parseInt(part,10),h);}
  return node;
}

/* ── BIP39 ── */
async function mnemonicToSeed(mn,pp=''){
  const enc=new TextEncoder();
  return pbkdf2Sha512(enc.encode(mn.normalize('NFKD')),enc.encode('mnemonic'+pp.normalize('NFKD')),2048,64);
}
let WORDLIST=null;
async function loadWordlist(){
  try{const r=await fetch('https://cdn.jsdelivr.net/npm/bip39@3.1.0/src/wordlists/english.json');WORDLIST=await r.json();}
  catch(e){WORDLIST=null;}
}
async function genMnemonic(strength){
  if(!WORDLIST){alert('Wordlist not ready, please wait.');return null;}
  const entropy=new Uint8Array(strength/8);crypto.getRandomValues(entropy);
  const h=await sha256u8(entropy),csBits=entropy.length/4;
  const bits=[...entropy].map(b=>b.toString(2).padStart(8,'0')).join('')+h[0].toString(2).padStart(8,'0').slice(0,csBits);
  const words=[];for(let i=0;i<bits.length;i+=11)words.push(WORDLIST[parseInt(bits.slice(i,i+11),2)]);
  return words.join(' ');
}
function validateMnemonic(words){if(!WORDLIST)return true;return words.every(w=>WORDLIST.includes(w));}

/* ── Dork Coin address generation (verified parameters) ── */
const DC={coinType:4151811,pubkeyAddress:0x1e,scriptAddress:0x08,secretKey:0x9e,segwitHrp:'dorkcoin',segwitHrpTestnet:'dorktest',taprootHrp:'dork'};
async function toWIF_d(k){const p=new Uint8Array(34);p[0]=DC.secretKey;p.set(k,1);p[33]=0x01;return bs58check(p);}
async function toLegacy_d(pub){const h=await hash160(pub),p=new Uint8Array(21);p[0]=DC.pubkeyAddress;p.set(h,1);return bs58check(p);}
async function toP2SH_d(pub){
  const h=await hash160(pub),rd=new Uint8Array(22);rd[0]=0x00;rd[1]=0x14;rd.set(h,2);
  const sh=await hash160(rd),p=new Uint8Array(21);p[0]=DC.scriptAddress;p.set(sh,1);return bs58check(p);
}
async function toNativeSegwit_d(pub){return bech32enc(DC.segwitHrp,0,await hash160(pub),false);}
async function toNativeSegwitTest_d(pub){return bech32enc(DC.segwitHrpTestnet,0,await hash160(pub),false);}
async function toTaproot_d(pub){return bech32enc(DC.taprootHrp,1,pub.slice(1,33),true);}

const ADDR_TYPES=[
  {name:'🏦 Legacy P2PKH — BIP44',         purpose:44,fn:toLegacy_d,           prefix:'D…',         color:'#f0c040'},
  {name:'🔀 SegWit P2SH — BIP49',          purpose:49,fn:toP2SH_d,             prefix:'4…',         color:'#5bc0de'},
  {name:'⚡ Native SegWit Mainnet — BIP84',purpose:84,fn:toNativeSegwit_d,     prefix:'dorkcoin1…', color:'#5cb85c'},
  {name:'🧪 Native SegWit Testnet — BIP84',purpose:84,fn:toNativeSegwitTest_d, prefix:'dorktest1…', color:'#f0ad4e'},
  {name:'🌿 Taproot P2TR — BIP86',         purpose:86,fn:toTaproot_d,          prefix:'dork1…',     color:'#d9534f'},
];

/* ── UI helpers ── */
function bip39Status(msg,isErr=false){
  const el=document.getElementById('bip39-status');if(!el)return;
  el.style.display='block';
  el.className='alert '+(isErr?'alert-danger':'alert-success');
  el.innerHTML=msg;
}
function mkCopy(val){
  const safe=val.replace(/\\/g,'\\\\').replace(/'/g,"\\'");
  return `<a class="btn btn-md btn-light text-heading align-items-center rounded" onclick="(function(b,v){navigator.clipboard.writeText(v);b.querySelector('span').textContent='✅ Copied!';setTimeout(()=>b.querySelector('span').textContent='📋 Copy',1500);})(this,'${safe}')"><span class="d-inline-block ff-1">📋 Copy</span></a>`;
}

async function bip39GenerateAll(){
  const mnemonic  =(document.getElementById('bip39-mnemonic')?.value||'').trim();
  const passphrase=document.getElementById('bip39-passphrase')?.value||'';
  const addrIdx   =parseInt(document.getElementById('bip39-addr-index')?.value||'0',10)||0;
  const acctIdx   =parseInt(document.getElementById('bip39-acct-index')?.value||'0',10)||0;
  const words=mnemonic.split(/\s+/);
  if(!mnemonic||words.length<12){document.getElementById('bip39-results').innerHTML='';return;}
  if(!validateMnemonic(words)){bip39Status('⚠️ Invalid mnemonic — one or more words not found in BIP39 wordlist.',true);return;}
  document.getElementById('bip39-results').innerHTML=
    '<div class="card mt-4"><div class="card-body text-center"><span class="text-secondary">⏳ Deriving keys, please wait...</span></div></div>';
  bip39Status('⏳ Deriving keys...');
  try{
    const seed=await mnemonicToSeed(mnemonic,passphrase);
    let html='';
    const qrData={};
    for(const type of ADDR_TYPES){
      try{
        const path=`m/${type.purpose}'/${DC.coinType}'/${acctIdx}'/0/${addrIdx}`;
        const node=await derivePath(seed,path);
        const pub=privToPub(node.key);
        const [addr,wif]=await Promise.all([type.fn(pub),toWIF_d(node.key)]);
        const pubHex=[...pub].map(b=>b.toString(16).padStart(2,'0')).join('');
        const qid=`${type.purpose}_${acctIdx}_${addrIdx}`;
        qrData[`a_${qid}`]=addr; qrData[`p_${qid}`]=wif;
        html+=`
          <div class="card mt-4">
            <div class="card-header d-flex justify-content-between align-items-center" style="border-left:3px solid ${type.color}">
              <span class="h5 mb-0">${type.name}</span>
              <span class="badge" style="background:${type.color};color:#000;font-family:monospace;font-size:.7rem;padding:4px 8px">${type.prefix}</span>
            </div>
            <div class="card-body">
              <div class="mb-3">
                <small class="text-secondary">🛤️ Derivation Path</small>
                <div class="field-value" style="font-size:.8rem;opacity:.7;margin-top:4px">${path}</div>
              </div>
              <div class="field-row mb-4">
                <div class="d-flex justify-content-between align-items-center">
                  <span class="h5 mb-0">📍 Public Address</span>
                  ${mkCopy(addr)}
                </div>
                <div class="field-value v-address mt-1" style="word-break:break-all">${addr}</div>
                <div class="mt-3 d-flex justify-content-center">
                  <div id="bip39qr_a_${qid}" class="qr-box"></div>
                </div>
                <div class="small text-muted mt-1">📷 QR Code – Public Address</div>
              </div>
              <div class="field-row mb-4">
                <div class="d-flex justify-content-between align-items-center">
                  <span class="h5 mb-0">🔑 Private Key (WIF)</span>
                  ${mkCopy(wif)}
                </div>
                <div class="field-value v-private mt-1" style="word-break:break-all">${wif}</div>
                <div class="mt-3 d-flex justify-content-center">
                  <div id="bip39qr_p_${qid}" class="qr-box"></div>
                </div>
                <div class="small text-muted mt-1">⚠️ QR Code – Private Key (Keep Secret!)</div>
              </div>
              <div class="field-row">
                <div class="d-flex justify-content-between align-items-center">
                  <span class="h5 mb-0">🔓 Public Key (compressed)</span>
                  ${mkCopy(pubHex)}
                </div>
                <div class="field-value v-pubkey mt-1" style="word-break:break-all;font-size:.72rem">${pubHex}</div>
              </div>
            </div>
          </div>`;
      }catch(err){
        html+=`<div class="card mt-4"><div class="card-header"><span class="h5 mb-0">${type.name}</span></div>
          <div class="card-body"><div class="field-value" style="color:#e94560">❌ ${err.message}</div></div></div>`;
      }
    }
    document.getElementById('bip39-results').innerHTML=html;
    setTimeout(()=>{
      for(const [k,v] of Object.entries(qrData)) renderQRDiv(`bip39qr_${k}`,v);
    },100);
    bip39Status(`✅ Done — Account ${acctIdx}, Index ${addrIdx} | Coin Type ${DC.coinType}`);
  }catch(err){
    document.getElementById('bip39-results').innerHTML=`<div class="card mt-4"><div class="card-body" style="color:#e94560">❌ ${err.message}</div></div>`;
    bip39Status('❌ '+err.message,true);
  }
}

/* ── Expose to global for onclick ── */
window.bip39GenerateAll=bip39GenerateAll;
window.bip39Gen12=async function(){const m=await genMnemonic(128);if(m){document.getElementById('bip39-mnemonic').value=m;bip39GenerateAll();}};
window.bip39Gen24=async function(){const m=await genMnemonic(256);if(m){document.getElementById('bip39-mnemonic').value=m;bip39GenerateAll();}};
window.bip39Paste=async function(){try{const t=await navigator.clipboard.readText();document.getElementById('bip39-mnemonic').value=t.trim();bip39GenerateAll();}catch(e){alert('Cannot read clipboard: '+e.message);}};
window.bip39Clear=function(){document.getElementById('bip39-mnemonic').value='';document.getElementById('bip39-results').innerHTML='';bip39Status('Mnemonic cleared.');};

/* ── Init ── */
bip39Status('⏳ Loading BIP39 wordlist...');
await loadWordlist();
bip39Status(WORDLIST?'✅ Ready — Enter mnemonic or click Generate 12 / 24 words.':'⚠️ Wordlist failed to load (offline?). You can still enter a mnemonic manually.',!WORDLIST);

['bip39-mnemonic','bip39-passphrase','bip39-addr-index','bip39-acct-index'].forEach(id=>{
  const el=document.getElementById(id);
  if(el)el.addEventListener('input',bip39GenerateAll);
});

})(); // end BIP39_MODULE
