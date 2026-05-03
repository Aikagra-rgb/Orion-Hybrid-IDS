/**
 * Threat Radar Module
 * Circular radar sweep animation with threat blips.
 */

export function initThreatRadar() {
  const canvas = document.getElementById('threatRadarCanvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let width, height, cx, cy, radius;
  let angle = 0;
  let animId;

  // Generate random threat blips
  const threats = Array.from({ length: 7 }, () => ({
    angle: Math.random() * Math.PI * 2,
    dist: 0.2 + Math.random() * 0.7,
    severity: ['critical', 'high', 'medium', 'low'][Math.floor(Math.random() * 4)],
    pulse: Math.random() * Math.PI * 2,
  }));

  const severityColors = {
    critical: '#ef5f5f',
    high: '#f0915f',
    medium: '#f0c541',
    low: '#6bb8ff',
  };

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const size = Math.min(rect.width, rect.height);
    width = rect.width;
    height = rect.height;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = width + 'px';
    canvas.style.height = height + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    cx = width / 2;
    cy = height / 2;
    radius = size / 2 - 20;
  }

  function drawGrid() {
    // Concentric rings
    for (let i = 1; i <= 4; i++) {
      ctx.beginPath();
      ctx.arc(cx, cy, (radius / 4) * i, 0, Math.PI * 2);
      ctx.strokeStyle = i === 4 ? 'rgba(35, 39, 47, 0.8)' : 'rgba(35, 39, 47, 0.4)';
      ctx.lineWidth = 0.5;
      ctx.stroke();
    }

    // Cross lines
    for (let i = 0; i < 4; i++) {
      const a = (Math.PI / 2) * i;
      ctx.beginPath();
      ctx.moveTo(cx, cy);
      ctx.lineTo(cx + Math.cos(a) * radius, cy + Math.sin(a) * radius);
      ctx.strokeStyle = 'rgba(35, 39, 47, 0.4)';
      ctx.lineWidth = 0.5;
      ctx.stroke();
    }

    // Center dot
    ctx.beginPath();
    ctx.arc(cx, cy, 3, 0, Math.PI * 2);
    ctx.fillStyle = '#6b7cff';
    ctx.fill();
  }

  function drawSweep() {
    const gradient = ctx.createConicGradient(angle, cx, cy);
    gradient.addColorStop(0, 'rgba(107, 124, 255, 0.15)');
    gradient.addColorStop(0.08, 'rgba(107, 124, 255, 0.08)');
    gradient.addColorStop(0.15, 'rgba(107, 124, 255, 0)');
    gradient.addColorStop(1, 'rgba(107, 124, 255, 0)');

    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.fillStyle = gradient;
    ctx.fill();

    // Sweep line
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.lineTo(cx + Math.cos(angle) * radius, cy + Math.sin(angle) * radius);
    ctx.strokeStyle = 'rgba(107, 124, 255, 0.6)';
    ctx.lineWidth = 1.5;
    ctx.stroke();
  }

  function drawThreats(time) {
    threats.forEach(t => {
      const x = cx + Math.cos(t.angle) * (t.dist * radius);
      const y = cy + Math.sin(t.angle) * (t.dist * radius);
      const color = severityColors[t.severity];
      const pulse = 1 + Math.sin(time * 0.003 + t.pulse) * 0.3;

      // Glow
      ctx.beginPath();
      ctx.arc(x, y, 8 * pulse, 0, Math.PI * 2);
      const r = parseInt(color.slice(1, 3), 16);
      const g = parseInt(color.slice(3, 5), 16);
      const b = parseInt(color.slice(5, 7), 16);
      ctx.fillStyle = `rgba(${r}, ${g}, ${b}, 0.15)`;
      ctx.fill();

      // Dot
      ctx.beginPath();
      ctx.arc(x, y, 3 * pulse, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
    });
  }

  function draw(time) {
    ctx.clearRect(0, 0, width, height);
    drawGrid();
    drawSweep();
    drawThreats(time);
    angle += 0.008;
    animId = requestAnimationFrame(draw);
  }

  resize();
  window.addEventListener('resize', resize);
  draw(0);

  // Update count badge
  const countEl = document.getElementById('radarThreatCount');
  if (countEl) countEl.textContent = `${threats.length} active`;

  return () => {
    cancelAnimationFrame(animId);
    window.removeEventListener('resize', resize);
  };
}
