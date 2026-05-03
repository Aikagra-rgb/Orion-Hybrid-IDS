/**
 * Alerts Module
 * Fetches live alerts, renders rows, handles AI integration and limits.
 */

let liveAlertsData = [];

async function fetchLiveAlerts() {
  try {
    const response = await fetch('/api/alerts');
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    
    liveAlertsData = await response.json();
    
    const activeFilterBtn = document.querySelector('.filter-btn--active');
    const currentFilter = activeFilterBtn ? activeFilterBtn.dataset.severity : 'all';
    
    renderAlerts(currentFilter);
  } catch (error) {
    console.error("[Orion] Failed to fetch live alerts:", error);
    const tbody = document.getElementById('alertsTableBody');
    if (tbody && liveAlertsData.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--red);">Connection to ORION Engine lost.</td></tr>`;
    }
  }
}

function renderAlerts(filter) {
  const tbody = document.getElementById('alertsTableBody');
  if (!tbody) return;

  const filtered = filter === 'all' 
    ? liveAlertsData 
    : liveAlertsData.filter(a => a.severity.toLowerCase() === filter.toLowerCase());

  if (filtered.length === 0) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-tertiary);">No alerts match this filter.</td></tr>`;
    return;
  }

  // LIMIT DASHBOARD CLUTTER: Only show 5 rows on Dashboard, show all on Alerts page
  const isDashboard = document.querySelector('.nav-item--active')?.dataset.page === 'dashboard';
  const itemsToRender = isDashboard ? filtered.slice(0, 5) : filtered;

  tbody.innerHTML = itemsToRender.map(alert => {
    const timeClean = alert.timestamp ? alert.timestamp.split('.')[0] : 'Unknown Time';
    const sevLower = alert.severity ? alert.severity.toLowerCase() : 'low';
    const status = 'open';

    // AI INTEL BUTTON LOGIC
    let intelCell = '<td style="color: var(--text-tertiary);">-</td>';
    if (alert.ai_report) {
      // Escape formatting so the alert box doesn't break
      const cleanReport = alert.ai_report.replace(/'/g, "\\'").replace(/"/g, "&quot;").replace(/\n/g, "\\n");
      
      intelCell = `<td>
        <button onclick="alert('=== ORION AI THREAT INTEL ===\\n\\n${cleanReport}')"
                style="background: rgba(167, 139, 250, 0.15); color: var(--purple); border: 1px solid var(--purple); padding: 4px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; cursor: pointer; transition: 0.2s;">
          🧠 View AI Intel
        </button>
      </td>`;
    }

    return `
      <tr>
        <td class="cell-timestamp">${timeClean}</td>
        <td class="cell-ip">${alert.source_ip}</td>
        <td>${alert.type}</td>
        <td><span class="severity-badge severity-badge--${sevLower}">${alert.severity}</span></td>
        <td>
          <span class="status-badge">
            <span class="status-badge__dot status-badge__dot--${status}"></span>
            ${status.charAt(0).toUpperCase() + status.slice(1)}
          </span>
        </td>
        ${intelCell}
      </tr>
    `;
  }).join('');
}

export function initAlerts() {
  let alertsPollInterval = null;

  fetchLiveAlerts();

  const filterBtns = document.querySelectorAll('.filter-btn');
  filterBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      filterBtns.forEach(b => b.classList.remove('filter-btn--active'));
      btn.classList.add('filter-btn--active');
      renderAlerts(btn.dataset.severity);
    });
  });

  alertsPollInterval = setInterval(fetchLiveAlerts, 3000);

  // Return cleanup function for the router to call on page change
  return () => {
    if (alertsPollInterval) clearInterval(alertsPollInterval);
    alertsPollInterval = null;
  };
}