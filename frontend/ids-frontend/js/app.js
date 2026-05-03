/**
 * Orion IDS Dashboard - Main Application
 * Component loader and module orchestrator.
 */

import { initSidebar } from './modules/sidebar.js?v=20260502-1';
import { initParallax } from './modules/parallax.js?v=20260502-1';
import { initSearch } from './modules/search.js?v=20260502-1';
import { navigateTo } from './modules/router.js?v=20260502-1';
import { initStatusBar } from './modules/statusbar.js?v=20260502-1';
import { initNotifications } from './modules/notifications.js?v=20260502-1';

const ORION_BUILD = '20260502-1';
let navigationDelegationBound = false;

/**
 * Load an HTML partial into a container element.
 */
async function loadComponent(url, target, mode = 'replace') {
  const el = typeof target === 'string' ? document.querySelector(target) : target;
  if (!el) {
    console.warn(`[Orion] Target not found for component: ${url}`);
    return;
  }

  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const html = await res.text();

    if (mode === 'append') {
      el.insertAdjacentHTML('beforeend', html);
    } else {
      el.innerHTML = html;
    }
  } catch (err) {
    console.error(`[Orion] Failed to load component ${url}:`, err);
  }
}

function bindGlobalNavigation() {
  if (navigationDelegationBound) return;
  navigationDelegationBound = true;

  document.body.addEventListener('click', async (event) => {
    const navItem = event.target.closest('.nav-item[data-page]');
    if (!navItem) return;

    event.preventDefault();
    event.stopPropagation();

    const page = navItem.dataset.page;
    if (page) {
      await navigateTo(page);
    }
  });
}

/**
 * Bootstrap - load shell components, then navigate to dashboard.
 */
async function bootstrap() {
  window.__ORION_BUILD__ = ORION_BUILD;
  document.documentElement.dataset.orionBuild = ORION_BUILD;

  await loadComponent('components/topbar.html', '#topbar-slot');
  await loadComponent('components/sidebar.html', '#sidebar-slot');
  await loadComponent('components/statusbar.html', '#statusbar-slot');
  await loadComponent('components/notifications.html', '#notif-slot');

  bindGlobalNavigation();
  initSidebar();
  initParallax();
  initSearch();
  initStatusBar();
  initNotifications();

  console.info(`[Orion] Frontend build ${ORION_BUILD} bootstrapped`);
  await navigateTo('dashboard');
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', bootstrap);
} else {
  bootstrap();
}
