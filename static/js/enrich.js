(function () {
  var clearForm = document.getElementById('clear-form');
  if (clearForm) {
    clearForm.addEventListener('submit', function (e) {
      if (!confirm('Delete all cached DNS data? This cannot be undone.')) {
        e.preventDefault();
      }
    });
  }

  var progressSection = document.getElementById('progress-section');
  if (!progressSection) return;

  var ipSection     = document.getElementById('ip-section');
  var domainSection = document.getElementById('domain-section');
  var ipBar         = document.getElementById('ip-bar');
  var domainBar     = document.getElementById('domain-bar');
  var ipCounter     = document.getElementById('ip-counter');
  var domainCounter = document.getElementById('domain-counter');
  var ipLog         = document.getElementById('ip-log');
  var domainLog     = document.getElementById('domain-log');
  var spfSection    = document.getElementById('spf-section');
  var spfBar        = document.getElementById('spf-bar');
  var spfCounter    = document.getElementById('spf-counter');
  var spfLog        = document.getElementById('spf-log');
  var tlsSection    = document.getElementById('tls-section');
  var tlsBar        = document.getElementById('tls-bar');
  var tlsCounter    = document.getElementById('tls-counter');
  var tlsLog        = document.getElementById('tls-log');
  var bimiSection   = document.getElementById('bimi-section');
  var bimiBar       = document.getElementById('bimi-bar');
  var bimiCounter   = document.getElementById('bimi-counter');
  var bimiLog       = document.getElementById('bimi-log');
  var doneBanner    = document.getElementById('done-banner');
  var progressTitle = document.getElementById('progress-title');
  var btn           = document.getElementById('start-btn');

  function appendLog(el, text) {
    var line = document.createElement('div');
    line.textContent = text;
    el.appendChild(line);
    el.scrollTop = el.scrollHeight;
  }

  function showIPProgress(done, total) {
    ipSection.style.display = '';
    ipBar.max = total || 1;
    ipBar.value = done;
    ipCounter.textContent = done + ' / ' + total;
  }

  function showDomainProgress(done, total) {
    domainSection.style.display = '';
    domainBar.max = total || 1;
    domainBar.value = done;
    domainCounter.textContent = done + ' / ' + total;
  }

  function showSPFProgress(done, total) {
    if (!spfSection) return;
    spfSection.style.display = '';
    spfBar.max = total || 1;
    spfBar.value = done;
    spfCounter.textContent = done + ' / ' + total;
  }

  function showTLSProgress(done, total) {
    if (!tlsSection) return;
    tlsSection.style.display = '';
    tlsBar.max = total || 1;
    tlsBar.value = done;
    tlsCounter.textContent = done + ' / ' + total;
  }

  function showBIMIProgress(done, total) {
    if (!bimiSection) return;
    bimiSection.style.display = '';
    bimiBar.max = total || 1;
    bimiBar.value = done;
    bimiCounter.textContent = done + ' / ' + total;
  }

  function showError(message) {
    progressTitle.textContent = 'Error';
    doneBanner.style.display = '';
    doneBanner.style.background = 'var(--pico-del-color-background,#ffebe9)';
    doneBanner.style.color = 'var(--pico-del-color,#82071e)';
    doneBanner.textContent = '✗ ' + (message || 'An error occurred. Check server logs.');
    if (btn) { btn.disabled = false; btn.textContent = 'Retry'; }
  }

  function showDone(ips, domains, spf, tls, bimi) {
    progressTitle.textContent = 'Complete';
    doneBanner.style.display = '';
    var suffix = '.';
    if (typeof ips === 'number' && typeof domains === 'number') {
      suffix = ' — ' + ips + ' IP(s) resolved, ' + domains + ' domain(s) checked';
      if (typeof spf === 'number') suffix += ', ' + spf + ' SPF record(s) expanded';
      if (typeof tls === 'number') suffix += ', ' + tls + ' domain(s) TLS-checked';
      if (typeof bimi === 'number') suffix += ', ' + bimi + ' BIMI record(s) checked';
      suffix += '.';
    }
    doneBanner.textContent = '✓ Enrichment complete' + suffix;
    if (btn) { btn.disabled = false; btn.textContent = 'Run Again'; }
  }

  function connect() {
    var es = new EventSource('/enrich/stream');

    // Sent once, immediately, with the worker's current state — lets a page
    // that loads mid-run (or after it already finished) render correctly
    // without waiting for the next per-item event.
    es.addEventListener('sync', function (e) {
      var d = JSON.parse(e.data);
      if (d.ip_total > 0) {
        showIPProgress(d.ip_done, d.ip_total);
        if (d.ip_done > 0) appendLog(ipLog, '… resuming (earlier items not shown)');
      }
      if (d.domain_total > 0) {
        showDomainProgress(d.domain_done, d.domain_total);
        if (d.domain_done > 0) appendLog(domainLog, '… resuming (earlier items not shown)');
      }
      if (d.tls_total > 0) {
        showTLSProgress(d.tls_done, d.tls_total);
        if (d.tls_done > 0) appendLog(tlsLog, '… resuming (earlier items not shown)');
      }
      if (d.spf_total > 0) {
        showSPFProgress(d.spf_done, d.spf_total);
        if (d.spf_done > 0) appendLog(spfLog, '… resuming (earlier items not shown)');
      }
      if (d.bimi_total > 0) {
        showBIMIProgress(d.bimi_done, d.bimi_total);
        if (d.bimi_done > 0) appendLog(bimiLog, '… resuming (earlier items not shown)');
      }
      if (!d.running) {
        es.close();
        if (d.error) {
          showError(d.error);
        } else if (d.ip_total > 0 || d.domain_total > 0 || d.spf_total > 0 || d.tls_total > 0 || d.bimi_total > 0) {
          showDone(d.ip_total, d.domain_total, d.spf_total, d.tls_total, d.bimi_total);
        }
      }
    });

    es.onmessage = function (e) {
      var d = JSON.parse(e.data);

      if (d.type === 'ip_start') {
        showIPProgress(0, d.total);
        if (d.total === 0) appendLog(ipLog, '(nothing to resolve)');
      } else if (d.type === 'ip') {
        showIPProgress(d.done, d.total);
        var flag = d.country ? ' [' + d.country + ']' : '';
        var mark = d.status === 'ok' ? '✓' : '✗';
        appendLog(ipLog, mark + ' ' + d.ip + flag);
      } else if (d.type === 'domain_start') {
        showDomainProgress(0, d.total);
        if (d.total === 0) appendLog(domainLog, '(nothing to check)');
      } else if (d.type === 'domain') {
        showDomainProgress(d.done, d.total);
        var badges = [];
        if (d.has_dmarc)   badges.push('DMARC');
        if (d.has_bimi)    badges.push('BIMI');
        if (d.has_mta_sts) badges.push('MTA-STS');
        appendLog(domainLog, '✓ ' + d.domain + (badges.length ? ' — ' + badges.join(', ') : ' — none'));
      } else if (d.type === 'tls_start') {
        showTLSProgress(0, d.total);
        if (d.total === 0) appendLog(tlsLog, '(nothing to check)');
      } else if (d.type === 'tls') {
        showTLSProgress(d.done, d.total);
        appendLog(tlsLog, (d.changed > 0 ? '~' : '·') + ' ' + d.domain + ' — ' + d.summary +
          (d.changed > 0 ? ' (' + d.changed + ' change(s))' : ''));
      } else if (d.type === 'bimi_start') {
        showBIMIProgress(0, d.total);
        if (d.total === 0) appendLog(bimiLog, '(nothing to check)');
      } else if (d.type === 'bimi') {
        showBIMIProgress(d.done, d.total);
        appendLog(bimiLog, (d.changed > 0 ? '~' : '·') + ' ' + d.domain + ' — ' + d.summary +
          (d.changed > 0 ? ' (' + d.changed + ' change(s))' : ''));
      } else if (d.type === 'spf_start') {
        showSPFProgress(0, d.total);
        if (d.total === 0) appendLog(spfLog, '(nothing to expand)');
      } else if (d.type === 'spf') {
        showSPFProgress(d.done, d.total);
        var mark = (d.error && d.cidrs === 0) ? '✗' : (d.over_limit ? '!' : '✓');
        appendLog(spfLog, mark + ' ' + d.domain + ' — ' + d.summary + (d.error && d.cidrs > 0 ? ' (' + d.error + ')' : ''));
      }
    };

    es.addEventListener('done', function (e) {
      es.close();
      var d = JSON.parse(e.data);
      showDone(d.ips, d.domains, d.spf, d.tls, d.bimi);
    });

    es.addEventListener('error', function (e) {
      es.close();
      showError();
    });
  }

  // If a run is already in progress (started from this tab earlier, another
  // tab, or before a page reload), pick up its live progress immediately.
  if (progressSection.dataset.running === 'true') {
    var ipDone      = parseInt(progressSection.dataset.ipDone, 10) || 0;
    var ipTotal     = parseInt(progressSection.dataset.ipTotal, 10) || 0;
    var domainDone  = parseInt(progressSection.dataset.domainDone, 10) || 0;
    var domainTotal = parseInt(progressSection.dataset.domainTotal, 10) || 0;
    var spfDone     = parseInt(progressSection.dataset.spfDone, 10) || 0;
    var spfTotal    = parseInt(progressSection.dataset.spfTotal, 10) || 0;
    var tlsDone     = parseInt(progressSection.dataset.tlsDone, 10) || 0;
    var tlsTotal    = parseInt(progressSection.dataset.tlsTotal, 10) || 0;
    var bimiDone    = parseInt(progressSection.dataset.bimiDone, 10) || 0;
    var bimiTotal   = parseInt(progressSection.dataset.bimiTotal, 10) || 0;
    if (ipTotal > 0) showIPProgress(ipDone, ipTotal);
    if (domainTotal > 0) showDomainProgress(domainDone, domainTotal);
    if (spfTotal > 0) showSPFProgress(spfDone, spfTotal);
    if (tlsTotal > 0) showTLSProgress(tlsDone, tlsTotal);
    if (bimiTotal > 0) showBIMIProgress(bimiDone, bimiTotal);
    connect();
  }
}());
