/* ============================================================
   PySentinel Report — JavaScript
   Features: collapsible sections, severity filter, live search
   ============================================================ */

(function () {
  'use strict';

  /* ── Collapsible sections ─────────────────────────────────── */
  function initAccordion() {
    document.querySelectorAll('.section-header').forEach(function (header) {
      header.addEventListener('click', function () {
        var section = header.closest('.section');
        section.classList.toggle('open');
      });
    });

    // Open sections that have findings by default
    document.querySelectorAll('.section[data-has-findings="true"]').forEach(function (s) {
      s.classList.add('open');
    });
    // Always open the summary section
    var summary = document.getElementById('section-summary');
    if (summary) summary.classList.add('open');
  }

  /* ── Active severity filter ───────────────────────────────── */
  var activeFilter = null;

  function applyFilter() {
    var searchText = (document.getElementById('search-input').value || '').toLowerCase();

    document.querySelectorAll('tbody tr[data-severity]').forEach(function (row) {
      var sev   = (row.getAttribute('data-severity') || '').toUpperCase();
      var text  = row.textContent.toLowerCase();
      var sevOk = !activeFilter || sev === activeFilter;
      var txtOk = !searchText  || text.indexOf(searchText) !== -1;
      row.classList.toggle('hidden', !(sevOk && txtOk));
    });

    // Update empty-state visibility per table
    document.querySelectorAll('.table-wrap').forEach(function (wrap) {
      var visible = wrap.querySelectorAll('tbody tr[data-severity]:not(.hidden)').length;
      var empty   = wrap.querySelector('.no-results-row');
      if (empty) empty.style.display = visible === 0 ? '' : 'none';
    });
  }

  function initFilters() {
    document.querySelectorAll('.filter-btn').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var sev = btn.getAttribute('data-sev');
        if (activeFilter === sev) {
          // Toggle off
          activeFilter = null;
          btn.classList.remove('active');
        } else {
          document.querySelectorAll('.filter-btn').forEach(function (b) {
            b.classList.remove('active');
          });
          activeFilter = sev;
          btn.classList.add('active');
        }
        applyFilter();
      });
    });
  }

  /* ── Live search ──────────────────────────────────────────── */
  function initSearch() {
    var input = document.getElementById('search-input');
    if (!input) return;
    input.addEventListener('input', applyFilter);
  }

  /* ── Copy-to-clipboard on code cells ─────────────────────── */
  function initCopyButtons() {
    document.querySelectorAll('.file-cell').forEach(function (cell) {
      var orig = cell.textContent;
      cell.addEventListener('click', function () {
        navigator.clipboard.writeText(orig).then(function () {
          cell.textContent = '✓ copied';
          cell.style.color = '#22c55e';
          setTimeout(function () {
            cell.textContent = orig;
            cell.style.color = '';
          }, 1200);
        }).catch(function () {});
      });
      cell.style.cursor = 'pointer';
      cell.title = 'Click to copy';
    });
  }

  /* ── Expand / collapse all toggle ────────────────────────── */
  function initExpandAll() {
    var btn = document.getElementById('expand-all');
    if (!btn) return;
    var expanded = false;
    btn.addEventListener('click', function () {
      expanded = !expanded;
      document.querySelectorAll('.section').forEach(function (s) {
        s.classList.toggle('open', expanded);
      });
      btn.textContent = expanded ? 'Collapse all' : 'Expand all';
    });
  }

  /* ── Animate score numbers ────────────────────────────────── */
  function animateScores() {
    document.querySelectorAll('.score-num').forEach(function (el) {
      var target = parseInt(el.textContent, 10);
      if (isNaN(target) || target === 0) return;
      var start = 0;
      var step  = Math.ceil(target / 20);
      var interval = setInterval(function () {
        start = Math.min(start + step, target);
        el.textContent = start;
        if (start >= target) clearInterval(interval);
      }, 30);
    });
  }

  /* ── Boot ─────────────────────────────────────────────────── */
  document.addEventListener('DOMContentLoaded', function () {
    initAccordion();
    initFilters();
    initSearch();
    initCopyButtons();
    initExpandAll();
    animateScores();
  });
})();
