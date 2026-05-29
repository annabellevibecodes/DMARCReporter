(function () {
  var clearForm = document.getElementById('clear-form');
  if (clearForm) {
    clearForm.addEventListener('submit', function (e) {
      if (!confirm('Delete all cached DNS data? This cannot be undone.')) {
        e.preventDefault();
      }
    });
  }

  var btn = document.getElementById('start-btn');
  if (!btn) return;
  var progressSection = document.getElementById('progress-section');

  btn.addEventListener('click', function () {
    btn.disabled = true;
    btn.textContent = 'Running…';
    progressSection.style.display = '';

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

    function appendLog(el, text) {
      var line = document.createElement('div');
      line.textContent = text;
      el.appendChild(line);
      el.scrollTop = el.scrollHeight;
    }

    var es = new EventSource('/enrich/stream');

    es.onmessage = function (e) {
      var d = JSON.parse(e.data);

      if (d.type === 'ip_start') {
        ipSection.style.display = '';
        ipBar.max = d.total || 1;
        ipBar.value = 0;
        ipCounter.textContent = '0 / ' + d.total;
        if (d.total === 0) {
          appendLog(ipLog, '(nothing to resolve)');
        }

      } else if (d.type === 'ip') {
        ipBar.value = d.done;
        ipBar.max   = d.total;
        ipCounter.textContent = d.done + ' / ' + d.total;
        var flag = d.country ? ' [' + d.country + ']' : '';
        var mark = d.status === 'ok' ? '✓' : '✗';
        appendLog(ipLog, mark + ' ' + d.ip + flag);

      } else if (d.type === 'domain_start') {
        domainSection.style.display = '';
        domainBar.max = d.total || 1;
        domainBar.value = 0;
        domainCounter.textContent = '0 / ' + d.total;
        if (d.total === 0) {
          appendLog(domainLog, '(nothing to check)');
        }

      } else if (d.type === 'domain') {
        domainBar.value = d.done;
        domainBar.max   = d.total;
        domainCounter.textContent = d.done + ' / ' + d.total;
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
      progressTitle.textContent = 'Complete';
      doneBanner.style.display = '';
      doneBanner.textContent = '✓ Enrichment complete — ' + d.ips + ' IP(s) resolved, ' + d.domains + ' domain(s) checked.';
      btn.textContent = 'Run Again';
      btn.disabled = false;
    });

    es.addEventListener('error', function (e) {
      es.close();
      progressTitle.textContent = 'Error';
      doneBanner.style.display = '';
      doneBanner.style.background = 'var(--pico-del-color-background,#ffebe9)';
      doneBanner.style.color = 'var(--pico-del-color,#82071e)';
      doneBanner.textContent = '✗ An error occurred. Check server logs.';
      btn.textContent = 'Retry';
      btn.disabled = false;
    });
  });
}());
