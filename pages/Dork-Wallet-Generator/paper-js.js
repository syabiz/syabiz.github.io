/* ============================================================
   PAPER WALLET — paper-js.js
   Dipanggil setelah generator.js
   ============================================================ */

/* ── Patch switchTab ── */
(function () {
  window.switchTab = function (tab, btn) {
    document.querySelectorAll('.tab-pane').forEach(function (t) {
      t.classList.remove('show', 'active');
    });
    var target = document.getElementById(tab + '-tab');
    if (target) target.classList.add('show', 'active');

    document.querySelectorAll('[data-bs-target][role="tab"]').forEach(function (b) {
      b.classList.remove('active');
    });
    if (btn) btn.classList.add('active');
  };
})();

/* ============================================================
   STATE
   ============================================================ */
var _pwCurrentWallet = null;

/* ============================================================
   GENERATE
   ============================================================ */
async function generatePaperWallet() {
  var resultEl = document.getElementById('pw-result');
  var genBtns  = document.querySelectorAll('[onclick="generatePaperWallet()"]');

  if (resultEl) resultEl.style.display = 'none';
  genBtns.forEach(function (b) { b.style.opacity = '0.6'; });

  // Beri waktu browser render sebelum operasi async berat
  await new Promise(function (r) { setTimeout(r, 60); });

  try {
    var entropy = crypto.getRandomValues(new Uint8Array(32));
    var w = await walletFromEntropy(entropy);
    _pwCurrentWallet = w;

    setText('pw-priv-key-text', w.wif);
    setText('pw-priv-hex-text', w.privHex);
    setText('pw-pub-addr-text', w.address);
    setText('pw-pub-key-text',  w.pubHex);

    var now = new Date();
    setText('pw-gen-date',
      now.toISOString().slice(0, 19).replace('T', ' ') + ' UTC');

    // Tampilkan result
    if (resultEl) resultEl.style.display = 'block';

    // Tunggu DOM update sebelum render QR
    await new Promise(function (r) { setTimeout(r, 100); });

    renderPaperQR('pw-pub-qr-container',  w.address, 114);
    renderPaperQR('pw-priv-qr-container', w.wif,     114);

  } catch (err) {
    alert('Gagal generate wallet: ' + err.message);
    console.error(err);
  }

  genBtns.forEach(function (b) { b.style.opacity = '1'; });
}

/* ── Helper set teks ── */
function setText(id, val) {
  var el = document.getElementById(id);
  if (el) el.textContent = val;
}

/* ── Render QR ke container ── */
function renderPaperQR(containerId, text, size) {
  var container = document.getElementById(containerId);
  if (!container) return;
  container.innerHTML = '';
  if (typeof QRCode === 'undefined') {
    container.innerHTML = '<span style="font-size:.6rem;color:#888;padding:4px;">QR N/A</span>';
    return;
  }
  try {
    new QRCode(container, {
      text: text,
      width:  size || 114,
      height: size || 114,
      colorDark:    '#000000',
      colorLight:   '#ffffff',
      correctLevel: QRCode.CorrectLevel.M
    });
    // qrcode.js render <img> — pastikan visible, sembunyikan canvas duplikat
    var img = container.querySelector('img');
    if (img) img.style.cssText = 'display:block;width:' + (size||114) + 'px;height:' + (size||114) + 'px;';
    var cvs = container.querySelector('canvas');
    if (cvs) cvs.style.display = 'none';
  } catch (e) {
    container.innerHTML = '<span style="font-size:.6rem;color:#888;padding:4px;">QR Error</span>';
    console.error('QR render error:', e);
  }
}

/* ============================================================
   PRINT
   ============================================================ */
function printPaperWallet() {
  if (!_pwCurrentWallet) { alert('Generate wallet dulu sebelum mencetak.'); return; }

  var card = document.getElementById('pw-card');
  if (!card) return;

  var pubQRImg  = document.querySelector('#pw-pub-qr-container img');
  var privQRImg = document.querySelector('#pw-priv-qr-container img');
  var clonedCard = card.cloneNode(true);

  _replaceQRInClone(clonedCard, 'pw-pub-qr-container',  pubQRImg,  114);
  _replaceQRInClone(clonedCard, 'pw-priv-qr-container', privQRImg, 114);

  var styleHTML = '';
  document.querySelectorAll('style').forEach(function (s) { styleHTML += s.outerHTML; });
  document.querySelectorAll('link[rel="stylesheet"]').forEach(function (l) { styleHTML += l.outerHTML; });

  var old = document.getElementById('__pw_print_iframe__');
  if (old) old.remove();

  var iframe = document.createElement('iframe');
  iframe.id = '__pw_print_iframe__';
  iframe.style.cssText = 'position:fixed;left:-9999px;top:-9999px;width:0;height:0;border:0;';
  document.body.appendChild(iframe);

  var iDoc = iframe.contentWindow.document;
  iDoc.open();
  iDoc.write('<!DOCTYPE html><html><head>' +
    '<meta charset="utf-8">' +
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>' +
    '<link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700&display=swap" rel="stylesheet">' +
    styleHTML +
    '<style>' +
    '@page{size:A5 landscape;margin:0;}' +
    'html,body{margin:0;padding:0;width:210mm;height:148mm;overflow:hidden;background:#fff;}' +
    '.pw-card{width:210mm!important;height:148mm!important;box-shadow:none!important;border:none!important;' +
    '-webkit-print-color-adjust:exact;print-color-adjust:exact;color-adjust:exact;}' +
    '.pw-fold-guide::before{display:none;}' +
    '</style>' +
    '</head><body>' + clonedCard.outerHTML + '</body></html>');
  iDoc.close();

  iframe.contentWindow.onload = function () {
    setTimeout(function () {
      iframe.contentWindow.focus();
      iframe.contentWindow.print();
    }, 500);
  };
}

function _replaceQRInClone(clonedCard, containerId, srcImg, size) {
  var c = clonedCard.querySelector('#' + containerId);
  if (!c) return;
  c.innerHTML = '';
  if (srcImg && srcImg.src) {
    var img = document.createElement('img');
    img.src = srcImg.src;
    img.style.cssText = 'display:block;width:' + size + 'px;height:' + size + 'px;';
    c.appendChild(img);
  }
}

/* ============================================================
   DOWNLOAD PDF
   ============================================================ */
async function downloadPaperWalletPDF() {
  if (!_pwCurrentWallet) { alert('Generate wallet dulu sebelum download PDF.'); return; }

  var btn = document.querySelector('[onclick="downloadPaperWalletPDF()"]');
  var origText = btn ? btn.querySelector('span').textContent : '';
  if (btn) { btn.querySelector('span').textContent = '⏳ Generating PDF…'; btn.style.opacity = '0.6'; }

  try {
    if (typeof html2canvas === 'undefined')
      await _pwLoadScript('https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js');
    if (typeof window.jspdf === 'undefined')
      await _pwLoadScript('https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js');

    var card = document.getElementById('pw-card');
    var canvas = await html2canvas(card, {
      scale: 3, useCORS: true, backgroundColor: null, logging: false,
      width: 735, height: 518
    });

    var pdf = new window.jspdf.jsPDF({ orientation: 'landscape', unit: 'mm', format: 'a5' });
    pdf.addImage(canvas.toDataURL('image/png'), 'PNG', 0, 0, 210, 148);
    pdf.save('dorkcoin-paper-wallet-' + _pwCurrentWallet.address.slice(0, 10) + '.pdf');

  } catch (err) {
    alert('Gagal generate PDF: ' + err.message);
    console.error(err);
  }

  if (btn) { btn.querySelector('span').textContent = origText; btn.style.opacity = '1'; }
}

function _pwLoadScript(src) {
  return new Promise(function (resolve, reject) {
    if (document.querySelector('script[src="' + src + '"]')) { resolve(); return; }
    var s = document.createElement('script');
    s.src = src; s.onload = resolve; s.onerror = reject;
    document.head.appendChild(s);
  });
}
