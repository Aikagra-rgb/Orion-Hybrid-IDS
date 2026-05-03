/**
 * Protocol Distribution Module
 * Doughnut chart showing breakdown of threat types from live backend data.
 */

const PROTOCOL_COLORS = [
  '#6b7cff', '#3dd68c', '#a78bfa', '#f0c541',
  '#ef5f5f', '#f0915f', '#6bb8ff', '#ff79a8',
];

export function initProtocolDist() {
  const canvas = document.getElementById('protocolCanvas');
  const totalEl = document.getElementById('protocolTotal');
  const legendEl = document.getElementById('protocolLegend');
  if (!canvas) return;

  let chartInstance = null;

  async function fetchAndRender() {
    try {
      const res = await fetch('/api/alerts');
      const alerts = await res.json();

      if (!Array.isArray(alerts) || alerts.length === 0) {
        if (totalEl) totalEl.textContent = '0 events';
        return;
      }

      // Count by alert type
      const counts = {};
      alerts.forEach((a) => {
        const key = a.type || 'Unknown';
        counts[key] = (counts[key] || 0) + 1;
      });

      const labels = Object.keys(counts);
      const data = Object.values(counts);
      const total = data.reduce((s, v) => s + v, 0);

      if (totalEl) totalEl.textContent = `${total} events`;

      // Destroy old instance
      const existing = Chart.getChart('protocolCanvas');
      if (existing) existing.destroy();

      chartInstance = new Chart(canvas, {
        type: 'doughnut',
        data: {
          labels,
          datasets: [
            {
              data,
              backgroundColor: labels.map((_, i) => PROTOCOL_COLORS[i % PROTOCOL_COLORS.length]),
              borderColor: 'rgba(15,17,21,0.8)',
              borderWidth: 2,
              hoverOffset: 8,
            },
          ],
        },
        options: {
          responsive: false,
          maintainAspectRatio: false,
          cutout: '68%',
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: (ctx) =>
                  ` ${ctx.label}: ${ctx.parsed} (${((ctx.parsed / total) * 100).toFixed(1)}%)`,
              },
            },
          },
        },
      });

      // Render custom legend
      if (legendEl) {
        legendEl.innerHTML = labels
          .map(
            (label, i) => `
          <span class="proto-legend-item">
            <span class="proto-dot" style="background:${PROTOCOL_COLORS[i % PROTOCOL_COLORS.length]}"></span>
            <span class="proto-label">${label}</span>
            <span class="proto-count">${data[i]}</span>
          </span>`
          )
          .join('');
      }
    } catch (err) {
      console.error('[Orion] Protocol distribution fetch failed:', err);
    }
  }

  fetchAndRender();
  const interval = setInterval(fetchAndRender, 10000);

  return () => clearInterval(interval);
}
