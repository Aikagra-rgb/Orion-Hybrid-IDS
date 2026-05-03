/**
 * Status Bar Module
 * Live clock, simulated CPU/memory fluctuations.
 */

export function initStatusBar() {
  const timeEl = document.getElementById('statusbarTime');
  const cpuEl = document.getElementById('cpuValue');
  const memEl = document.getElementById('memValue');

  function updateClock() {
    if (timeEl) {
      const now = new Date();
      timeEl.textContent = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    }
  }

  function fluctuateStats() {
    if (cpuEl) {
      const cpu = Math.floor(18 + Math.random() * 15);
      cpuEl.textContent = cpu + '%';
    }
    if (memEl) {
      const mem = (3.8 + Math.random() * 1.2).toFixed(1);
      memEl.textContent = mem + ' GB';
    }
  }

  updateClock();
  fluctuateStats();

  setInterval(updateClock, 1000);
  setInterval(fluctuateStats, 5000);
}
