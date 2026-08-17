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

  function showError(message) {
    progressTitle.textContent = 'Error';
    doneBanner.style.display = '';
    doneBanner.style.background = 'var(--pico-del-color-background,#ffebe9)';
    doneBanner.style.color = 'var(--pico-del-color,#82071e)';
    doneBanner.textContent = '✗ ' + (message || 'An error occurred. Check server logs.');
    if (btn) { btn.disabled = false; btn.textContent = 'Retry'; }
  }

  function showDone(ips, domains) {
    progressTitle.textContent = 'Complete';
    doneBanner.style.display = '';
    var suffix = (typeof ips === 'number' && typeof domains === 'number')
      ? ' — ' + ips + ' IP(s) resolved, ' + domains + ' domain(s) checked.'
      : '.';
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
      if (!d.running) {
        es.close();
        if (d.error) {
          showError(d.error);
        } else if (d.ip_total > 0 || d.domain_total > 0) {
          showDone(d.ip_total, d.domain_total);
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
      }
    };

    es.addEventListener('done', function (e) {
      es.close();
      var d = JSON.parse(e.data);
      showDone(d.ips, d.domains);
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
    if (ipTotal > 0) showIPProgress(ipDone, ipTotal);
    if (domainTotal > 0) showDomainProgress(domainDone, domainTotal);
    connect();
  }
}());
