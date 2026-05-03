/**
 * AI Analyst Module
 * Replaces the Threat Radar. Automatically displays the latest AI Triage report.
 */

export function initAiAnalyst() {
  const container = document.getElementById('aiAnalystContent');
  if (!container) return;

  let lastReportId = null;

  async function fetchAiIntel() {
    try {
      const res = await fetch('/api/alerts');
      const alerts = await res.json();

      // Find the most recent alert that contains an AI report
      const aiAlert = alerts.find(a => a.ai_report && a.ai_report.trim() !== '');

      if (aiAlert) {
        // Only update the DOM if it's a new report
        if (aiAlert.id !== lastReportId) {
          lastReportId = aiAlert.id;
          
          // Convert plaintext newlines into HTML breaks
          const cleanReport = aiAlert.ai_report.replace(/\n/g, '<br>');
          
          container.innerHTML = `
            <div style="margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid var(--border-subtle);">
              <span style="color: var(--text-tertiary); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em;">Target IP Identified</span><br>
              <strong style="font-family: var(--font-mono); color: var(--text-primary); font-size: 1.1rem;">${aiAlert.source_ip}</strong>
              <div style="color: var(--text-tertiary); font-size: 0.75rem; margin-top: 4px;">Time: ${aiAlert.timestamp}</div>
            </div>
            <div style="color: var(--text-primary); font-weight: 600; margin-bottom: 8px;">Automated Triage Analysis:</div>
            <div style="padding: 12px; background: rgba(167, 139, 250, 0.08); border-left: 3px solid var(--purple); border-radius: 4px; font-size: 0.85rem; line-height: 1.6; color: var(--text-secondary);">
              ${cleanReport}
            </div>
          `;
        }
      } else {
        container.innerHTML = `
          <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: var(--text-tertiary); text-align: center;">
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="margin-bottom: 12px; opacity: 0.5;">
              <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
            </svg>
            <div>No AI reports generated yet.<br>Awaiting Honeypot triggers.</div>
          </div>
        `;
      }
    } catch (e) {
      console.error('[Orion] AI Analyst fetch error:', e);
    }
  }

  // Fetch immediately, then check every 3 seconds
  fetchAiIntel();
  const pollInterval = setInterval(fetchAiIntel, 3000);

  return () => clearInterval(pollInterval);
}