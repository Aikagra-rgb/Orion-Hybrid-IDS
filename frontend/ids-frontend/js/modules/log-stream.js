/**
 * Log Stream Module
 * Renders live backend detections, dynamically limiting dashboard clutter.
 */

function escapeHtml(value = '') {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatTime(timestamp) {
  if (!timestamp) return 'Unknown';

  const parsed = new Date(timestamp);
  if (Number.isNaN(parsed.getTime())) {
    return timestamp;
  }

  return parsed.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function normalizeLevel(log) {
  const rawLevel = (log.level || log.severity || 'info').toLowerCase();
  if (rawLevel === 'critical' || rawLevel === 'high') return 'error';
  if (rawLevel === 'medium') return 'warn';
  if (rawLevel === 'low') return 'info';
  return ['info', 'warn', 'error', 'debug'].includes(rawLevel) ? rawLevel : 'info';
}

export function initLogStream() {
  const container = document.getElementById('logStream');
  const pauseBtn = document.getElementById('logPauseBtn');
  const clearBtn = document.getElementById('logClearBtn');
  if (!container) return;

  let paused = false;
  let intervalId = null;

  async function fetchLogs() {
    if (paused) return;

    try {
      // LIMIT LOGS CLUTTER: 20 on Dashboard, 120 on full Logs page
      const activeNav = document.querySelector('.nav-item--active');
      const isDashboard = activeNav && activeNav.dataset.page === 'dashboard';
      const limit = isDashboard ? 20 : 120;

      const response = await fetch(`/api/logs?limit=${limit}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);

      const logs = await response.json();
      if (!Array.isArray(logs) || logs.length === 0) {
        container.innerHTML = '<div class="log-entry"><span class="log-time">--:--:--</span><span class="log-level log-level--info">INFO </span><span class="log-source">[ids.engine]</span><span class="log-msg">Waiting for new detections...</span></div>';
        return;
      }

      const orderedLogs = [...logs].reverse();
      container.innerHTML = orderedLogs.map((log) => {
        const level = normalizeLevel(log);
        return `
          <div class="log-entry">
            <span class="log-time">${escapeHtml(formatTime(log.timestamp))}</span>
            <span class="log-level log-level--${level}">${escapeHtml(level.toUpperCase().padEnd(5))}</span>
            <span class="log-source">[${escapeHtml(log.source || 'ids.engine')}]</span>
            <span class="log-msg">${escapeHtml(log.message || `${log.alert_type || 'Alert'} detected`)}</span>
          </div>
        `;
      }).join('');

      container.scrollTop = container.scrollHeight;
    } catch (error) {
      console.error('[Orion] Failed to fetch logs:', error);
      container.innerHTML = '<div class="log-entry"><span class="log-time">--:--:--</span><span class="log-level log-level--error">ERROR</span><span class="log-source">[ids.engine]</span><span class="log-msg">Live log feed unavailable.</span></div>';
    }
  }

  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      paused = !paused;
      pauseBtn.innerHTML = paused
        ? '<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><path d="M4 2l8 5-8 5V2z" fill="currentColor"/></svg>'
        : '<svg width="14" height="14" viewBox="0 0 14 14" fill="none"><rect x="3" y="2" width="3" height="10" rx="0.5" fill="currentColor"/><rect x="8" y="2" width="3" height="10" rx="0.5" fill="currentColor"/></svg>';
    });
  }

  if (clearBtn) {
    clearBtn.addEventListener('click', () => {
      container.innerHTML = '';
    });
  }

  fetchLogs();
  intervalId = setInterval(fetchLogs, 3000);

  return () => {
    if (intervalId) clearInterval(intervalId);
  };
}