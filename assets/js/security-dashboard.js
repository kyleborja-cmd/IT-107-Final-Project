(function () {
  'use strict';

  const dashboard = document.getElementById('security-dashboard');
  if (!dashboard) return;

  const filters = document.getElementById('security-filters');
  const errorBox = document.getElementById('dashboard-error');
  const refreshLabel = document.getElementById('last-refresh');
  const chartCanvas = document.getElementById('failed-login-chart');
  const chartReading = document.getElementById('failed-login-reading');
  const chartScale = document.getElementById('failed-login-scale');
  let selectedHour;
  const refreshButton = document.getElementById('refresh-security');
  const sectionLinks = document.querySelectorAll('.security-section-nav .side-link');
  let appliedQuery = currentQuery();
  let pendingRequest;

  function addCell(row, value, className) {
    const cell = document.createElement('td');
    cell.textContent = value === null || value === undefined || value === '' ? '-' : String(value);
    if (className) cell.className = className;
    row.appendChild(cell);
    return cell;
  }

  function setEmptyRow(body, columns, message) {
    const row = document.createElement('tr');
    const cell = addCell(row, message, 'empty-state');
    cell.colSpan = columns;
    body.replaceChildren(row);
  }

  function displayIp(address) {
    return address === '::1' || address === '127.0.0.1' ? '127.0.0.1 (Localhost)' : address;
  }

  function renderTopIps(ips) {
    const body = document.getElementById('top-ip-rows');
    body.replaceChildren();
    if (!ips.length) {
      setEmptyRow(body, 4, 'No failed login events in the last 24 hours.');
      return;
    }
    ips.forEach(function (item) {
      const row = document.createElement('tr');
      addCell(row, displayIp(item.ip_address));
      addCell(row, item.failures);
      const status = addCell(row, item.blocked ? 'Blocked' : 'Not Blocked');
      status.className = item.blocked ? 'status-cell status-blocked' : 'status-cell status-clear';
      addCell(row, item.expires_at);
      body.appendChild(row);
    });
  }

  function renderFlags(flags) {
    const body = document.getElementById('security-flag-rows');
    body.replaceChildren();
    if (!flags.length) {
      setEmptyRow(body, 5, 'No security flags have been generated yet.');
      return;
    }
    flags.forEach(function (item) {
      const row = document.createElement('tr');
      addCell(row, item.flag_type);
      const severity = addCell(row, item.severity);
      severity.className = 'severity-' + String(item.severity).toLowerCase();
      addCell(row, item.flag_type === 'IP_OVER_THRESHOLD' ? displayIp(item.affected_target) : item.affected_target);
      addCell(row, item.description);
      addCell(row, item.detected_at);
      body.appendChild(row);
    });
  }

  function renderIpBlocks(blocks) {
    const body = document.getElementById('ip-block-rows');
    body.replaceChildren();
    if (!blocks.length) {
      setEmptyRow(body, 5, 'No IP blocks recorded in the last 24 hours.');
      return;
    }
    for (const block of blocks) {
      const row = document.createElement('tr');
      addCell(row, displayIp(block.ip_address));
      addCell(row, block.username);
      addCell(row, block.active ? 'Active' : 'Expired', block.active ? 'status-cell status-blocked' : 'status-cell status-clear');
      addCell(row, block.blocked_at);
      addCell(row, block.expires_at);
      body.appendChild(row);
    }
  }

  function renderEvents(events) {
    const body = document.getElementById('security-event-rows');
    body.replaceChildren();
    if (!events.length) {
      setEmptyRow(body, 7, 'No security events match the selected filters.');
      return;
    }
    events.forEach(function (item) {
      const row = document.createElement('tr');
      addCell(row, item.id);
      addCell(row, item.created_at);
      addCell(row, item.status, 'event-status');
      addCell(row, item.username_typed);
      addCell(row, item.user_id);
      addCell(row, displayIp(item.ip_address));
      addCell(row, item.user_agent);


      body.appendChild(row);
    });
  }

  function renderChart(data) {
    const step = Math.max(1, Math.ceil(Math.max(...data.values) / 4));
    const maximum = step * 4;
    chartScale.replaceChildren(...[4, 3, 2, 1, 0].map(tick => {
      const label = document.createElement('span');
      label.textContent = String(tick * step);
      return label;
    }));
    const focusedHour = document.activeElement?.dataset.chartHour;
    chartCanvas.replaceChildren();
    const bars = data.hours.map((hour, index) => {
      const value = data.values[index];
      const bucket = document.createElement('button');
      bucket.type = 'button';
      bucket.className = 'hourly-chart-bucket';
      bucket.dataset.chartHour = hour.key;
      const countLabel = value === 1 ? '1 failed sign-in' : `${value} failed sign-ins`;
      const reading = `${hour.start} to ${hour.end} (PH time): ${countLabel}${hour.in_progress ? ' so far' : ''}.`;
      bucket.title = reading;
      bucket.setAttribute('aria-label', reading);
      const bar = document.createElement('meter');
      bar.max = maximum;
      bar.value = value;
      bar.setAttribute('aria-hidden', 'true');
      const time = document.createElement('small');
      time.textContent = hour.tick;
      bucket.append(bar, time);
      bucket.addEventListener('click', () => selectHour(index));
      bucket.addEventListener('focus', () => selectHour(index));
      bucket.addEventListener('keydown', event => {
        const direction = event.key === 'ArrowLeft' ? -1 : event.key === 'ArrowRight' ? 1 : 0;
        if (!direction) return;
        event.preventDefault();
        bars[index + direction]?.focus();
      });
      return bucket;
    });
    chartCanvas.append(...bars);

    function selectHour(index) {
      selectedHour = data.hours[index].key;
      bars.forEach((button, position) => {
        button.tabIndex = position === index ? 0 : -1;
        button.setAttribute('aria-pressed', String(position === index));
      });
      if (chartReading.textContent !== bars[index].title) chartReading.textContent = bars[index].title;
    }
    const selected = data.hours.findIndex(hour => hour.key === selectedHour);
    selectHour(selected >= 0 ? selected : bars.length - 1);
    if (selected < 0) chartCanvas.parentElement.scrollLeft = chartCanvas.parentElement.scrollWidth;
    if (focusedHour) bars.find(button => button.dataset.chartHour === focusedHour)?.focus({ preventScroll: true });
  }

  function currentQuery() {
    const params = new URLSearchParams();
    new FormData(filters).forEach(function (value, key) {
      if (typeof value === 'string' && value.trim() !== '') params.set(key, value.trim());
    });
    return params.toString();
  }

  async function refresh() {
    pendingRequest?.abort();
    const request = new AbortController();
    pendingRequest = request;
    refreshButton.disabled = true;
    const endpoint = dashboard.dataset.endpoint;
    try {
      const response = await fetch(endpoint + (appliedQuery ? '?' + appliedQuery : ''), {
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
        cache: 'no-store',
        signal: request.signal
      });
      const data = await response.json().catch(() => null);
      if (!response.ok) {
        throw new Error(data?.error || 'Security data could not be loaded. Sign in again if your session has expired.');
      }
      if (request.signal.aborted) return;
      if (!data) throw new Error('Security data could not be read.');
      Object.keys(data.summary).forEach(function (key) {
        const element = dashboard.querySelector('[data-summary="' + key + '"]');
        if (element) element.textContent = String(data.summary[key]);
      });
      renderChart(data.chart);
      renderTopIps(data.top_ips);
      renderIpBlocks(data.ip_blocks);
      renderFlags(data.flags);
      renderEvents(data.events);
      refreshLabel.textContent = data.last_refresh;
      errorBox.hidden = true;
    } catch (error) {
      if (request.signal.aborted) return;
      errorBox.textContent = error.message || 'Security data could not be loaded.';
      errorBox.hidden = false;
    } finally {
      if (pendingRequest === request) {
        refreshButton.disabled = false;
      }
    }
  }

  filters.addEventListener('submit', function (event) {
    event.preventDefault();
    appliedQuery = currentQuery();
    refresh();
  });
  filters.addEventListener('reset', function (event) {
    event.preventDefault();
    for (const input of filters.querySelectorAll('input, select')) input.value = '';
    appliedQuery = '';
    refresh();
  });
  refreshButton.addEventListener('click', refresh);

  function markSection() {
    const active = window.location.hash || '#security-overview';
    sectionLinks.forEach(link => {
      const selected = link.hash === active;
      link.classList.toggle('selected', selected);
      if (selected) link.setAttribute('aria-current', 'location');
      else link.removeAttribute('aria-current');
    });
  }
  markSection();
  window.addEventListener('hashchange', markSection);

  refresh();
  const refreshTimer = window.setInterval(refresh, 60000);
  window.addEventListener('beforeunload', function () {
    window.clearInterval(refreshTimer);
    pendingRequest?.abort();
  });
}());
