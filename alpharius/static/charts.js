// Renders the overview charts from the JSON block the server embeds in the page.
(function () {
  const el = document.getElementById("chart-data");
  if (!el || !window.Chart) return;
  const data = JSON.parse(el.textContent);
  const css = getComputedStyle(document.documentElement);
  const v = (name) => css.getPropertyValue(name).trim();
  const muted = v("--muted"), line = v("--line"), text = v("--text");

  Chart.defaults.color = muted;
  Chart.defaults.borderColor = line;
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily;
  Chart.defaults.plugins.legend.labels.boxWidth = 10;
  Chart.defaults.maintainAspectRatio = false;

  const SOURCE_COLORS = { urlhaus: "#e0a43a", threatfox: "#c678dd", feodo: "#e5534b" };
  const PALETTE = ["#2ec4b6", "#5fa8d3", "#c678dd", "#e0a43a", "#e5534b", "#3fb68b", "#9aa5ce", "#d19a66", "#56b6c2", "#be5046"];

  function empty(id) {
    const c = document.getElementById(id);
    const p = document.createElement("p");
    p.className = "muted";
    p.textContent = "No data yet.";
    c.parentElement.replaceChildren(p);
  }

  function chart(id, config, hasData) {
    if (!hasData) return empty(id);
    new Chart(document.getElementById(id), config);
  }

  // New indicators per day, stacked by feed
  const daily = data.daily;
  chart("c-daily", {
    type: "bar",
    data: {
      labels: daily.labels.map((d) => d.slice(5)),
      datasets: Object.entries(daily.series).map(([src, counts]) => ({
        label: src, data: counts, backgroundColor: SOURCE_COLORS[src] || PALETTE[0], borderRadius: 3,
      })),
    },
    options: { scales: { x: { stacked: true, grid: { display: false } }, y: { stacked: true, beginAtZero: true } } },
  }, daily.labels.length > 0);

  const horizontal = (id, rows, color) => chart(id, {
    type: "bar",
    data: { labels: rows.map((r) => r.label), datasets: [{ data: rows.map((r) => r.n), backgroundColor: color, borderRadius: 3 }] },
    options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, ticks: { precision: 0 } }, y: { grid: { display: false }, ticks: { color: text } } } },
  }, rows.length > 0);

  horizontal("c-malware", data.malware, v("--accent"));
  horizontal("c-countries", data.countries, "#e5534b");

  chart("c-kev", {
    type: "line",
    data: {
      labels: data.kev.labels,
      datasets: [
        { label: "added to KEV", data: data.kev.total, borderColor: v("--accent-2"), backgroundColor: v("--accent-2"), tension: 0.3, pointRadius: 2 },
        { label: "ransomware use known", data: data.kev.ransomware, borderColor: "#e5534b", backgroundColor: "#e5534b", tension: 0.3, pointRadius: 2 },
      ],
    },
    options: { scales: { y: { beginAtZero: true }, x: { grid: { display: false } } } },
  }, data.kev.labels.length > 0);

  chart("c-types", {
    type: "doughnut",
    data: { labels: data.types.map((r) => r.label), datasets: [{ data: data.types.map((r) => r.n), backgroundColor: PALETTE, borderColor: v("--panel"), borderWidth: 2 }] },
    options: { cutout: "62%", plugins: { legend: { position: "right" } } },
  }, data.types.length > 0);

  chart("c-matches", {
    type: "bar",
    data: { labels: data.matches.labels.map((d) => d.slice(5)), datasets: [{ label: "matches", data: data.matches.counts, backgroundColor: "#e5534b", borderRadius: 3 }] },
    options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } }, x: { grid: { display: false } } } },
  }, data.matches.labels.length > 0);
})();
