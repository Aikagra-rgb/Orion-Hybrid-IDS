/**
 * Counters Module
 * Animated number counters with IntersectionObserver trigger.
 */

export function animateCounter(el) {
  const target = parseFloat(el.dataset.target);
  if (isNaN(target)) return; 

  const isFloat = el.classList.contains('stat-card__value--health');
  const duration = 1200;
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    const current = target * eased;

    if (isFloat) {
      el.textContent = current.toFixed(1) + '%';
    } else {
      el.textContent = Math.floor(current).toLocaleString();
    }

    if (progress < 1) {
      requestAnimationFrame(update);
    }
  }

  requestAnimationFrame(update);
}

export async function initCounters() {
  // 1. Fetch live data from ORION
  try {
    const response = await fetch('/api/alerts');
    if (response.ok) {
      const alerts = await response.json();
      
      // Calculate real-time stats
      const totalAlerts = alerts.length;
      const criticalAlerts = alerts.filter(a => a.severity === 'Critical' || a.severity === 'High').length;
      const uniqueIPs = new Set(alerts.map(a => a.source_ip)).size;
      
      // Dynamic System Health: Drops based on critical threats (min 15%)
      let systemHealth = 100.0 - (criticalAlerts * 1.2);
      if (systemHealth < 15.0) systemHealth = 15.0;

      // Update the data-targets in the HTML using querySelector
      const threatsEl = document.querySelector('#cardThreats .stat-card__value');
      if (threatsEl) threatsEl.dataset.target = totalAlerts;

      // Repurposing "Active Connections" to show "Unique Blocked IPs"
      const connectionsEl = document.querySelector('#cardConnections .stat-card__value');
      if (connectionsEl) connectionsEl.dataset.target = uniqueIPs;

      const healthEl = document.querySelector('#cardHealth .stat-card__value');
      if (healthEl) healthEl.dataset.target = systemHealth;
      
      // Note: We leave cardPackets alone so it just animates the dummy data, 
      // since the database only logs malicious packets, not all packets.
    }
  } catch (err) {
    console.error("[Orion] Failed to fetch live counter stats:", err);
  }

  // 2. Start the animations
  const counterEls = document.querySelectorAll('.stat-card__value');
  if (!counterEls.length) return;

  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          animateCounter(entry.target);
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.5 }
  );

  counterEls.forEach(el => observer.observe(el));

  return { counterEls, animateCounter };
}