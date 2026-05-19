function initTrendChart(canvasId, data) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels,
            datasets: [
                {
                    label: 'Passed',
                    data: data.passed,
                    borderColor: '#198754',
                    backgroundColor: 'rgba(25, 135, 84, 0.1)',
                    fill: true,
                    tension: 0.3,
                },
                {
                    label: 'Failed',
                    data: data.failed,
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    fill: true,
                    tension: 0.3,
                },
            ],
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'top' },
                title: { display: false },
            },
            scales: {
                y: { beginAtZero: true, title: { display: true, text: 'Messages' } },
                x: { title: { display: true, text: 'Week' } },
            },
        },
    });
}

function initDoughnutChart(canvasId, labels, values, colors) {
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors,
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            plugins: {
                legend: { position: 'bottom' },
                title: { display: false },
            },
        },
    });
}

// initThemedTrendChart renders the trend chart with custom theme colors.
function initThemedTrendChart(canvasId, data, theme) {
    var ctx = document.getElementById(canvasId);
    if (!ctx || typeof Chart === 'undefined') return;
    var existing = Chart.getChart(ctx);
    if (existing) existing.destroy();

    var themes = {
        goth: {
            passed: { borderColor: '#d4d0c8', backgroundColor: 'rgba(212,208,200,0.08)', tension: 0 },
            failed: { borderColor: '#c1121f', backgroundColor: 'rgba(193,18,31,0.15)', tension: 0 },
            ticks: { color: '#6e6a60', font: { family: "'IBM Plex Mono', monospace", size: 10 } },
            grid: { color: '#1a1a1e' },
            pointRadius: 2, borderWidth: 1.5
        },
        pink: {
            passed: { borderColor: '#ff2d8b', backgroundColor: 'rgba(255,45,139,0.12)', fill: true, tension: 0.3 },
            failed: { borderColor: '#c8a2ff', backgroundColor: 'rgba(200,162,255,0.1)', fill: false, tension: 0.3 },
            ticks: { color: '#a06080', font: { family: "'Manrope', sans-serif", size: 11 } },
            grid: { color: '#fde7f0' },
            pointRadius: 3, borderWidth: 2.5
        },
        blue: {
            passed: { borderColor: '#0e2a4a', backgroundColor: 'rgba(14,42,74,0.06)', fill: false, tension: 0, pointBackgroundColor: '#b08d3e' },
            failed: { borderColor: '#6b1f24', backgroundColor: 'rgba(107,31,36,0.12)', fill: true, tension: 0 },
            ticks: { color: '#6b5e3c', font: { family: "'Source Serif 4', Georgia, serif", size: 11 } },
            grid: { color: '#d8cfb7' },
            pointRadius: 3, borderWidth: 1.5,
            xMaxRotation: 45
        }
    };

    var t = themes[theme];
    if (!t) return;

    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.labels || [],
            datasets: [
                { label: 'Passed', data: data.passed || [], borderColor: t.passed.borderColor, backgroundColor: t.passed.backgroundColor, borderWidth: t.borderWidth, pointRadius: t.pointRadius, pointBackgroundColor: t.passed.pointBackgroundColor || t.passed.borderColor, fill: t.passed.fill !== undefined ? t.passed.fill : false, tension: t.passed.tension },
                { label: 'Failed', data: data.failed || [], borderColor: t.failed.borderColor, backgroundColor: t.failed.backgroundColor, borderWidth: t.failed.borderWidth || t.borderWidth, pointRadius: t.pointRadius, pointBackgroundColor: t.failed.pointBackgroundColor || t.failed.borderColor, fill: t.failed.fill !== undefined ? t.failed.fill : false, tension: t.failed.tension }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: t.xMaxRotation ? { color: t.ticks.color, font: t.ticks.font, maxRotation: t.xMaxRotation } : t.ticks, grid: t.grid },
                y: { ticks: t.ticks, grid: t.grid }
            }
        }
    });
}

// Auto-initialise the global compliance trend chart (skip if a themed chart already rendered it).
(function () {
    const canvas = document.getElementById('trend-chart');
    if (!canvas || Chart.getChart(canvas)) return;
    const el = document.getElementById('trend-data');
    if (!el) return;
    try {
        const data = JSON.parse(el.textContent);
        if (data && data.labels && data.labels.length > 0) {
            initTrendChart('trend-chart', data);
        }
    } catch (e) {}
}());

// Auto-initialise the failure mode doughnut chart.
(function () {
    const el = document.getElementById('failure-mode-data');
    if (!el) return;
    try {
        const data = JSON.parse(el.textContent);
        if (data && data.labels && data.values) {
            initDoughnutChart('failure-mode-chart', data.labels, data.values, [
                '#198754', // DKIM only pass — green
                '#fd7e14', // SPF only pass — amber
                '#dc3545', // Both fail — red
            ]);
        }
    } catch (e) {}
}());

// Auto-initialise the per-domain trend chart.
(function () {
    const el = document.getElementById('domain-trend-data');
    if (!el) return;
    try {
        const data = JSON.parse(el.textContent);
        if (data && data.labels && data.labels.length > 0) {
            initTrendChart('domain-trend-chart', data);
        }
    } catch (e) {}
}());

// initPieChart renders a doughnut chart from a JSON data script tag.
// colors is an optional array of background color strings.
function initPieChart(canvasId, dataScriptId, colors) {
    const el = document.getElementById(dataScriptId);
    if (!el) return;
    var data;
    try { data = JSON.parse(el.textContent); } catch (e) { return; }
    if (!data || !data.labels || !data.values) return;
    const ctx = document.getElementById(canvasId);
    if (!ctx) return;
    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: data.labels,
            datasets: [{
                data: data.values,
                backgroundColor: colors || ['#198754', '#fd7e14', '#dc3545', '#6c757d'],
                borderWidth: 2,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { boxWidth: 12, padding: 10 } },
            },
        },
    });
}

// Auto-initialise the three dashboard pie charts.
(function () {
    initPieChart('policy-pie-chart', 'policy-pie-data', ['#6c757d', '#fd7e14', '#dc3545']);
    initPieChart('bimi-pie-chart',   'bimi-pie-data',   ['#198754', '#dee2e6']);
    initPieChart('mtasts-pie-chart', 'mtasts-pie-data', ['#0d6efd', '#dee2e6']);
}());
