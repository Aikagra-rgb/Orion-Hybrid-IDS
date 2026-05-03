/**
 * Router Module
 * Handles component loading, page transitions, and module initialization.
 */
import { initCounters } from './counters.js?v=20260502-1';
import { initAlerts } from './alerts.js?v=20260502-1';
import { initCharts } from './charts.js?v=20260502-1';
import { initNetworkMap } from './network-map.js?v=20260502-1';
import { initAiAnalyst } from './ai-analyst.js?v=20260502-1';
import { initLogStream } from './log-stream.js?v=20260502-1';
import { initSecurityGauge } from './security-gauge.js?v=20260502-1';
import { initThreatRadar } from './threat-radar.js?v=20260502-1';
import { initProtocolDist } from './protocol-dist.js?v=20260502-1';

const PAGE_CONFIG = {
  dashboard: {
    components: [
      'components/stats.html',
      'components/charts.html',
      'components/visualizations.html',
      'components/alerts.html',
    ],
    init: async () => {
      await initCounters();
      waitForChart(initCharts);
      const alertsCleanup = initAlerts();
      return [
        alertsCleanup,
        initNetworkMap(),
        initAiAnalyst(),
        initLogStream(),
        initSecurityGauge(),
        initThreatRadar(),
        initProtocolDist(),
      ];
    },
    title: 'Dashboard',
    subtitle: 'Real-time network monitoring and threat intelligence',
  },
  network: {
    page: 'pages/network.html',
    init: async () => {
      waitForChart(initCharts);
      return initNetworkMap();
    },
    title: 'Network Activity',
    subtitle: 'Traffic patterns, topology, and bandwidth trends',
  },
  threats: {
    page: 'pages/threats.html',
    init: async () => {
      await initCounters();
      waitForChart(initCharts);
      return [
        initAiAnalyst(),
        initSecurityGauge(),
        initThreatRadar(),
      ];
    },
    title: 'Threat Detection',
    subtitle: 'Threat posture, severity distribution, and active detections',
  },
  alerts: {
    page: 'pages/alerts.html',
    init: async () => {
      return initAlerts();
    },
    title: 'Alerts',
    subtitle: 'Investigate recent detections and filter by severity',
  },
  logs: {
    page: 'pages/logs.html',
    init: async () => initLogStream(),
    title: 'Logs',
    subtitle: 'Live engine event stream built from backend detections',
  },
  settings: {
    page: 'pages/settings.html',
    title: 'Settings',
    subtitle: 'Tune the IDS engine and operator preferences',
    init: null,
  },
};

let currentPage = null;
let cleanupFns = [];

function waitForChart(fn) {
  if (window.Chart) {
    Chart.defaults.font.family = "'Inter', sans-serif";
    Chart.defaults.color = '#8b8f9a';
    fn();
  } else {
    setTimeout(() => waitForChart(fn), 100);
  }
}

function registerCleanup(candidate) {
  if (!candidate) return;

  if (Array.isArray(candidate)) {
    candidate.forEach(registerCleanup);
    return;
  }

  if (typeof candidate === 'function') {
    cleanupFns.push(candidate);
  }
}

async function loadPageContent(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } catch (err) {
    return `<div class="page-error">Failed to load content: ${err.message}</div>`;
  }
}

export async function navigateTo(page) {
  if (page === currentPage) return;

  const config = PAGE_CONFIG[page];
  if (!config) return;

  const mainContent = document.getElementById('mainContent');
  if (!mainContent) return;

  // Safe Cleanup Loop prevents broken tabs
  cleanupFns.forEach((fn) => {
    try {
      if (typeof fn === 'function') fn();
    } catch (e) {
      console.warn(`[Router] Cleanup error on ${page}:`, e);
    }
  });
  cleanupFns = [];

  const headerHTML = `
    <div class="main__header">
      <div>
        <h1 class="main__title">${config.title}</h1>
        <p class="main__subtitle">${config.subtitle}</p>
      </div>
      <div class="main__actions">
        <span class="last-updated" id="lastUpdated">Updated just now</span>
        <button class="btn btn--outline" id="refreshBtn">Refresh</button>
      </div>
    </div>
    <div id="pageComponents"></div>
  `;
  mainContent.innerHTML = headerHTML;

  const componentContainer = document.getElementById('pageComponents');
  if (!componentContainer) return;

  if (config.components) {
    for (const url of config.components) {
      const html = await loadPageContent(url);
      componentContainer.insertAdjacentHTML('beforeend', html);
    }
  } else if (config.page) {
    const html = await loadPageContent(config.page);
    componentContainer.insertAdjacentHTML('beforeend', html);
  }

  // Safe Module Initialization
  if (config.init) {
    try {
      const cleanup = await config.init();
      registerCleanup(cleanup);
    } catch (err) {
      console.error(`[Router] Module initialization failed for ${page}:`, err);
    }
  }

  const refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) {
    refreshBtn.onclick = () => {
      currentPage = null;
      navigateTo(page);
    };
  }

  currentPage = page;
  document.title = `Orion - ${config.title}`;
  document.querySelectorAll('.nav-item').forEach((item) => {
    item.classList.toggle('nav-item--active', item.dataset.page === page);
  });
}