/**
 * Security Gauge Module
 * Arc gauge showing system security health score.
 */

export function initSecurityGauge() {
  const canvas = document.getElementById('securityGaugeCanvas');
  const valueEl = document.getElementById('gaugeValue');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let TARGET_SCORE = 87; // default until API responds
  let currentScore = 0;
  let animId;

  // Fetch live score from backend
  fetch('/api/stats')
    .then((r) => r.json())
    .then((stats) => {
      if (stats && typeof stats.critical_alerts === 'number') {
        let score = 100.0 - stats.critical_alerts * 1.5;
        if (score < 10) score = 10;
        TARGET_SCORE = Math.round(score);
      }
    })
    .catch(() => {});

  function resize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const size = Math.min(rect.width - 40, rect.height - 60, 200);
    canvas.width = size * dpr;
    canvas.height = size * dpr;
    canvas.style.width = size + 'px';
    canvas.style.height = size + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function getColor(score) {
    if (score >= 80) return '#3dd68c';
    if (score >= 60) return '#f0c541';
    if (score >= 40) return '#f0915f';
    return '#ef5f5f';
  }

  function drawGauge(score) {
    const w = parseInt(canvas.style.width);
    const h = parseInt(canvas.style.height);
    const cx = w / 2;
    const cy = h / 2 + 10;
    const r = Math.min(w, h) / 2 - 12;
    const lineWidth = 10;
    const startAngle = Math.PI * 0.75;
    const endAngle = Math.PI * 2.25;
    const totalArc = endAngle - startAngle;

    ctx.clearRect(0, 0, w, h);

    // Background track
    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, endAngle);
    ctx.strokeStyle = 'rgba(35, 39, 47, 0.8)';
    ctx.lineWidth = lineWidth;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Score arc
    const scoreAngle = startAngle + (score / 100) * totalArc;
    const color = getColor(score);

    ctx.beginPath();
    ctx.arc(cx, cy, r, startAngle, scoreAngle);
    ctx.strokeStyle = color;
    ctx.lineWidth = lineWidth;
    ctx.lineCap = 'round';
    ctx.stroke();

    // Glow on arc end
    const endX = cx + Math.cos(scoreAngle) * r;
    const endY = cy + Math.sin(scoreAngle) * r;
    ctx.beginPath();
    ctx.arc(endX, endY, lineWidth, 0, Math.PI * 2);
    const rr = parseInt(color.slice(1, 3), 16);
    const gg = parseInt(color.slice(3, 5), 16);
    const bb = parseInt(color.slice(5, 7), 16);
    ctx.fillStyle = `rgba(${rr}, ${gg}, ${bb}, 0.15)`;
    ctx.fill();

    // Tick marks
    for (let i = 0; i <= 10; i++) {
      const tickAngle = startAngle + (i / 10) * totalArc;
      const inner = r - lineWidth / 2 - 6;
      const outer = r - lineWidth / 2 - (i % 5 === 0 ? 14 : 10);
      ctx.beginPath();
      ctx.moveTo(cx + Math.cos(tickAngle) * inner, cy + Math.sin(tickAngle) * inner);
      ctx.lineTo(cx + Math.cos(tickAngle) * outer, cy + Math.sin(tickAngle) * outer);
      ctx.strokeStyle = 'rgba(92, 97, 112, 0.4)';
      ctx.lineWidth = i % 5 === 0 ? 1.5 : 0.8;
      ctx.stroke();
    }

    // Labels 0 and 100
    ctx.fillStyle = '#5c6170';
    ctx.font = "500 9px 'JetBrains Mono', monospace";
    ctx.textAlign = 'center';
    const labelR = r + lineWidth / 2 + 10;
    ctx.fillText('0', cx + Math.cos(startAngle) * labelR, cy + Math.sin(startAngle) * labelR + 4);
    ctx.fillText('100', cx + Math.cos(endAngle) * labelR, cy + Math.sin(endAngle) * labelR + 4);
  }

  function animate() {
    if (currentScore < TARGET_SCORE) {
      currentScore += (TARGET_SCORE - currentScore) * 0.04 + 0.3;
      if (currentScore > TARGET_SCORE) currentScore = TARGET_SCORE;
    }

    drawGauge(currentScore);
    if (valueEl) valueEl.textContent = Math.round(currentScore);

    if (currentScore < TARGET_SCORE) {
      animId = requestAnimationFrame(animate);
    }
  }

  resize();
  window.addEventListener('resize', () => {
    resize();
    drawGauge(currentScore);
  });

  // Trigger animation when visible
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          animate();
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.3 }
  );

  observer.observe(canvas.closest('.viz-card') || canvas);

  return () => cancelAnimationFrame(animId);
}
