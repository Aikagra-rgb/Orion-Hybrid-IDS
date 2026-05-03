/**
 * Charts Module - ORION INTEGRATED
 * Connects Chart.js visualizations to the real Python backend.
 * Uses Chart.getChart() for safe destruction before re-init.
 */

/** Safely destroy any existing Chart instance on a canvas before creating a new one. */
function safeDestroyChart(canvasId) {
  const existing = Chart.getChart(canvasId);
  if (existing) existing.destroy();
}

// Helper to process SQLite alerts into Chart.js friendly format
function processAlertsForCharts(alerts) {
  const labels = [];
  const critical = [], high = [], medium = [], low = [];

  // Create hourly buckets for the last 12 hours
  const buckets = {};
  const now = new Date();
  for (let i = 11; i >= 0; i--) {
    const d = new Date(now - i * 3600000);
    const label = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    labels.push(label);
    buckets[label] = { Critical: 0, High: 0, Medium: 0, Low: 0 };
  }

  // Sort alerts into buckets
  alerts.forEach((alert) => {
    const alertTime = new Date(alert.timestamp);
    const label = alertTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const bucketLabel = labels.find((l) => l.split(':')[0] === label.split(':')[0]);
    if (bucketLabel && buckets[bucketLabel]) {
      const sev =
        alert.severity.charAt(0).toUpperCase() + alert.severity.slice(1).toLowerCase();
      if (buckets[bucketLabel][sev] !== undefined) {
        buckets[bucketLabel][sev]++;
      }
    }
  });

  labels.forEach((l) => {
    critical.push(buckets[l].Critical);
    high.push(buckets[l].High);
    medium.push(buckets[l].Medium);
    low.push(buckets[l].Low);
  });

  return { labels, critical, high, medium, low };
}

async function createThreatChart(alerts) {
  const ctx = document.getElementById('threatCanvas');
  if (!ctx) return null;

  safeDestroyChart('threatCanvas');
  const data = processAlertsForCharts(alerts);

  return new Chart(ctx, {
    type: 'bar',
    data: {
      labels: data.labels,
      datasets: [
        {
          label: 'Critical',
          data: data.critical,
          backgroundColor: 'rgba(239,95,95,0.75)',
          borderRadius: 2,
        },
        {
          label: 'High',
          data: data.high,
          backgroundColor: 'rgba(240,145,95,0.7)',
          borderRadius: 2,
        },
        {
          label: 'Medium',
          data: data.medium,
          backgroundColor: 'rgba(240,197,65,0.6)',
          borderRadius: 2,
        },
        {
          label: 'Low',
          data: data.low,
          backgroundColor: 'rgba(107,184,255,0.5)',
          borderRadius: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: true, position: 'top', align: 'end' },
      },
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: { stacked: true, grid: { color: 'rgba(35,39,47,0.5)' } },
      },
    },
  });
}

function createTrafficChart() {
  const ctx = document.getElementById('trafficCanvas');
  if (!ctx) return null;

  safeDestroyChart('trafficCanvas');

  const timeLabels = Array.from({ length: 20 }, (_, i) => `-${20 - i}s`);
  const incomingData = Array.from({ length: 20 }, () => Math.floor(Math.random() * 50) + 20);
  const outgoingData = Array.from({ length: 20 }, () => Math.floor(Math.random() * 30) + 10);

  const chart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: timeLabels,
      datasets: [
        {
          label: 'Ingress (Mbps)',
          data: incomingData,
          borderColor: '#3dd68c',
          backgroundColor: 'rgba(61, 214, 140, 0.08)',
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        },
        {
          label: 'Egress (Mbps)',
          data: outgoingData,
          borderColor: '#6b7cff',
          backgroundColor: 'rgba(107, 124, 255, 0.08)',
          fill: true,
          tension: 0.4,
          pointRadius: 0,
          borderWidth: 2,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 0 },
      plugins: {
        legend: { display: true, position: 'top', align: 'end' },
      },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 5 } },
        y: {
          beginAtZero: true,
          max: 100,
          grid: { color: 'rgba(35,39,47,0.5)' },
        },
      },
    },
  });

  // Live-update the traffic chart every second (stop when canvas is gone)
  const liveInterval = setInterval(() => {
    if (!document.getElementById('trafficCanvas')) {
      clearInterval(liveInterval);
      return;
    }
    chart.data.datasets[0].data.shift();
    chart.data.datasets[0].data.push(Math.floor(Math.random() * 50) + 20);
    chart.data.datasets[1].data.shift();
    chart.data.datasets[1].data.push(Math.floor(Math.random() * 30) + 10);
    chart.update('none');
  }, 1000);

  return chart;
}

export async function initCharts() {
  if (typeof Chart === 'undefined') return;

  try {
    const response = await fetch('/api/alerts');
    const alerts = await response.json();
    createTrafficChart();
    await createThreatChart(alerts);
  } catch (err) {
    console.error('[Orion] Chart data fetch failed:', err);
    // Still render the traffic chart even if backend is down
    createTrafficChart();
  }

  // Tab switching UI feedback
  document.querySelectorAll('.chart-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const parent = tab.closest('.chart-card__controls');
      parent.querySelectorAll('.chart-tab').forEach((t) => t.classList.remove('chart-tab--active'));
      tab.classList.add('chart-tab--active');
    });
  });
}