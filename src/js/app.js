/**
 * CVE Prioritiser - Frontend Application Logic
 * Serverless Vulnerability Intelligence Dashboard
 */

document.addEventListener('DOMContentLoaded', () => {
  // App State
  const state = {
    allCVEs: [],
    filteredCVEs: [],
    activeCategory: 'all',
    activeVendor: null,
    searchQuery: '',
    minCVSS: 0,
    minEPSS: 0,
    sortBy: 'cvss-desc',
    currentPage: 1,
    pageSize: 24
  };

  // Dom Elements
  const el = {
    lastUpdated: document.getElementById('last-updated'),
    statTotal: document.getElementById('stat-total-cves'),
    statKev: document.getElementById('stat-kev-cves'),
    statImmediate: document.getElementById('stat-immediate-patch'),
    statHigh: document.getElementById('stat-high-priority'),
    
    heatmapGrid: document.getElementById('heatmap-grid'),
    heatmapFilterIndicator: document.getElementById('heatmap-filter-indicator'),
    filteredVendorName: document.getElementById('filtered-vendor-name'),
    clearVendorFilter: document.getElementById('clear-vendor-filter'),
    
    tabAll: document.getElementById('tab-all'),
    tabImmediate: document.getElementById('tab-immediate'),
    tabHigh: document.getElementById('tab-high'),
    tabScheduled: document.getElementById('tab-scheduled'),
    tabWatchlist: document.getElementById('tab-watchlist'),
    
    countAll: document.getElementById('count-all'),
    countImmediate: document.getElementById('count-immediate'),
    countHigh: document.getElementById('count-high'),
    countScheduled: document.getElementById('count-scheduled'),
    countWatchlist: document.getElementById('count-watchlist'),
    
    searchInput: document.getElementById('search-input'),
    cvssSlider: document.getElementById('cvss-slider'),
    cvssVal: document.getElementById('cvss-val'),
    epssSlider: document.getElementById('epss-slider'),
    epssVal: document.getElementById('epss-val'),
    sortSelect: document.getElementById('sort-select'),
    
    cveContainer: document.getElementById('cve-cards-container'),
    emptyState: document.getElementById('empty-state'),
    resetFiltersBtn: document.getElementById('reset-filters-btn'),
    paginationContainer: document.getElementById('pagination-container'),
    countShown: document.getElementById('count-shown'),
    countTotal: document.getElementById('count-total'),
    loadMoreBtn: document.getElementById('load-more-btn'),
    
    drawerBackdrop: document.getElementById('drawer-backdrop'),
    drawer: document.getElementById('remediation-drawer'),
    closeDrawerBtn: document.getElementById('close-drawer'),
    
    drawerCveId: document.getElementById('drawer-cve-id'),
    drawerTitle: document.getElementById('drawer-title'),
    drawerCvssScore: document.getElementById('drawer-cvss-score'),
    drawerCvssVersion: document.getElementById('drawer-cvss-version'),
    drawerEpssScore: document.getElementById('drawer-epss-score'),
    drawerEpssPercentile: document.getElementById('drawer-epss-percentile'),
    drawerRansomwareAlert: document.getElementById('drawer-ransomware-alert'),
    drawerVendor: document.getElementById('drawer-vendor'),
    drawerProduct: document.getElementById('drawer-product'),
    drawerDateAdded: document.getElementById('drawer-date-added'),
    drawerDueDateContainer: document.getElementById('drawer-due-date-container'),
    drawerDueDate: document.getElementById('drawer-due-date'),
    drawerActionCallout: document.getElementById('drawer-action-callout'),
    drawerTacticalAction: document.getElementById('drawer-tactical-action'),
    drawerDescription: document.getElementById('drawer-description'),
    drawerRemediationSection: document.getElementById('drawer-remediation-section'),
    drawerRequiredAction: document.getElementById('drawer-required-action'),
    btnCopyRemediation: document.getElementById('btn-copy-remediation'),
    drawerReferences: document.getElementById('drawer-references')
  };

  // 1. Initialise & Fetch Data
  async function init() {
    try {
      const response = await fetch('src/data/cve-data.json');
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }
      const data = await response.ok ? await response.json() : null;
      if (!data) return;
      
      // Load data into state
      state.allCVEs = data.cves || [];
      
      // Update Sync Status
      if (data.last_updated) {
        const date = new Date(data.last_updated);
        el.lastUpdated.textContent = `Sync Status: Daily update completed ${date.toLocaleDateString()} ${date.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}`;
      }
      
      // Calculate Stats & Categories
      calculateStatsAndDrawHeatmap();
      
      // Apply initial filters
      applyFilters();
      
    } catch (error) {
      console.error('Failed to load CVE database:', error);
      el.cveContainer.innerHTML = `
        <div class="empty-state">
          <div class="empty-icon">⚠️</div>
          <h3>Failed to load vulnerability database</h3>
          <p>The JSON database is either compiling or unavailable. Please run the data sync script.</p>
        </div>
      `;
    }
  }

  // 2. Classify Vulnerability
  function getTriageCategory(cve) {
    const cvss = cve.cvss !== null ? cve.cvss : 0.0;
    const epss = cve.epss || 0.0;
    const inKev = cve.in_kev;
    
    if (inKev) {
      return 'immediate';
    } else if (cvss >= 7.0 && epss > 0.10) {
      return 'high';
    } else if (cvss >= 7.0) {
      return 'scheduled';
    } else {
      return 'watchlist';
    }
  }

  // 3. Stats Calculation & Vendor Heatmap Renders
  function calculateStatsAndDrawHeatmap() {
    let total = state.allCVEs.length;
    let kev = 0;
    let immediate = 0;
    let high = 0;
    let scheduled = 0;
    let watchlist = 0;
    
    const vendorCounts = {};
    
    state.allCVEs.forEach(cve => {
      // Counts
      if (cve.in_kev) kev++;
      
      const cat = getTriageCategory(cve);
      if (cat === 'immediate') immediate++;
      else if (cat === 'high') high++;
      else if (cat === 'scheduled') scheduled++;
      else if (cat === 'watchlist') watchlist++;
      
      // Vendor grouping
      const vendor = cve.vendor || 'Unknown';
      if (vendor !== 'Unknown') {
        vendorCounts[vendor] = (vendorCounts[vendor] || 0) + 1;
      }
    });
    
    // Animate KPI values
    animateValue(el.statTotal, 0, total, 1000);
    animateValue(el.statKev, 0, kev, 1000);
    animateValue(el.statImmediate, 0, immediate, 1000);
    animateValue(el.statHigh, 0, high, 1000);
    
    // Tab badges
    el.countAll.textContent = total;
    el.countImmediate.textContent = immediate;
    el.countHigh.textContent = high;
    el.countScheduled.textContent = scheduled;
    el.countWatchlist.textContent = watchlist;
    
    // Heatmap - Sort vendors and render top 10
    const sortedVendors = Object.entries(vendorCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);
      
    renderHeatmap(sortedVendors);
  }

  function animateValue(obj, start, end, duration) {
    if (start === end) {
      obj.textContent = end;
      return;
    }
    let startTimestamp = null;
    const step = (timestamp) => {
      if (!startTimestamp) startTimestamp = timestamp;
      const progress = Math.min((timestamp - startTimestamp) / duration, 1);
      obj.textContent = Math.floor(progress * (end - start) + start);
      if (progress < 1) {
        window.requestAnimationFrame(step);
      }
    };
    window.requestAnimationFrame(step);
  }

  function renderHeatmap(vendors) {
    el.heatmapGrid.innerHTML = '';
    
    if (vendors.length === 0) {
      el.heatmapGrid.innerHTML = '<div class="loading-spinner-inline">No vendor data available.</div>';
      return;
    }
    
    // Find max value for scaling intensity
    const maxCount = vendors[0][1];
    
    vendors.forEach(([name, count]) => {
      const block = document.createElement('div');
      block.className = 'heatmap-block';
      
      // Determine intensity class
      let intensity = 'intensity-none';
      const pct = count / maxCount;
      if (pct > 0.6) intensity = 'intensity-high';
      else if (pct > 0.25) intensity = 'intensity-medium';
      else if (pct > 0.05) intensity = 'intensity-low';
      
      block.classList.add(intensity);
      if (state.activeVendor === name) {
        block.classList.add('active-filter');
      }
      
      block.innerHTML = `
        <div class="heatmap-block-name">${name}</div>
        <div class="heatmap-block-count">${count}</div>
      `;
      
      block.addEventListener('click', () => {
        if (state.activeVendor === name) {
          state.activeVendor = null;
          block.classList.remove('active-filter');
          el.heatmapFilterIndicator.style.display = 'none';
        } else {
          // Clear any active blocks
          document.querySelectorAll('.heatmap-block').forEach(b => b.classList.remove('active-filter'));
          state.activeVendor = name;
          block.classList.add('active-filter');
          el.filteredVendorName.textContent = name;
          el.heatmapFilterIndicator.style.display = 'flex';
        }
        state.currentPage = 1;
        applyFilters();
      });
      
      el.heatmapGrid.appendChild(block);
    });
  }

  // 4. Filtering and Sorting logic
  function applyFilters() {
    state.filteredCVEs = state.allCVEs.filter(cve => {
      // Tab Category filter
      if (state.activeCategory !== 'all') {
        const cat = getTriageCategory(cve);
        if (cat !== state.activeCategory) return false;
      }
      
      // Heatmap Vendor filter
      if (state.activeVendor && cve.vendor !== state.activeVendor) {
        return false;
      }
      
      // Min CVSS filter
      const cvss = cve.cvss !== null ? cve.cvss : 0;
      if (cvss < state.minCVSS) return false;
      
      // Min EPSS filter
      const epssPct = (cve.epss || 0) * 100;
      if (epssPct < state.minEPSS) return false;
      
      // Search Box filter
      if (state.searchQuery) {
        const query = state.searchQuery.toLowerCase();
        const matchesId = cve.cve_id.toLowerCase().includes(query);
        const matchesVendor = (cve.vendor || '').toLowerCase().includes(query);
        const matchesProduct = (cve.product || '').toLowerCase().includes(query);
        const matchesRansom = (cve.ransomware || '').toLowerCase().includes(query);
        const matchesDesc = (cve.description || '').toLowerCase().includes(query);
        const matchesTitle = (cve.title || '').toLowerCase().includes(query);
        
        if (!matchesId && !matchesVendor && !matchesProduct && !matchesRansom && !matchesDesc && !matchesTitle) {
          return false;
        }
      }
      
      return true;
    });
    
    // Sort Results
    sortCVEs();
    
    // Render
    renderGrid();
  }

  function sortCVEs() {
    state.filteredCVEs.sort((a, b) => {
      if (state.sortBy === 'cvss-desc') {
        const scoreA = a.cvss !== null ? a.cvss : -1;
        const scoreB = b.cvss !== null ? b.cvss : -1;
        return scoreB - scoreA;
      } else if (state.sortBy === 'epss-desc') {
        return (b.epss || 0) - (a.epss || 0);
      } else if (state.sortBy === 'date-desc') {
        // Fall back to empty string if date is missing
        const dateA = a.date_added || '';
        const dateB = b.date_added || '';
        return dateB.localeCompare(dateA);
      } else if (state.sortBy === 'cve-asc') {
        return a.cve_id.localeCompare(b.cve_id);
      }
      return 0;
    });
  }

  // 5. Grid Rendering
  function renderGrid() {
    const totalCount = state.filteredCVEs.length;
    el.countTotal.textContent = totalCount;
    
    if (state.currentPage === 1) {
      el.cveContainer.innerHTML = '';
    }
    
    if (totalCount === 0) {
      el.cveContainer.innerHTML = '';
      el.emptyState.style.display = 'flex';
      el.paginationContainer.style.display = 'none';
      return;
    }
    
    el.emptyState.style.display = 'none';
    
    // Slice according to pagination
    const startIdx = (state.currentPage - 1) * state.pageSize;
    const endIdx = Math.min(startIdx + state.pageSize, totalCount);
    
    const slice = state.filteredCVEs.slice(startIdx, endIdx);
    
    slice.forEach(cve => {
      const card = createCard(cve);
      el.cveContainer.appendChild(card);
    });
    
    el.countShown.textContent = endIdx;
    
    // Handle "Load More" button visibility
    if (endIdx < totalCount) {
      el.paginationContainer.style.display = 'flex';
    } else {
      el.paginationContainer.style.display = 'none';
    }
  }

  function createCard(cve) {
    const card = document.createElement('div');
    card.className = 'cve-card';
    if (cve.in_kev) {
      card.classList.add('in-kev-active');
    }
    
    // Determine CVSS severity color class
    let cvssSeverity = 'low';
    const cvss = cve.cvss;
    if (cvss !== null) {
      if (cvss >= 9.0) cvssSeverity = 'critical';
      else if (cvss >= 7.0) cvssSeverity = 'high';
      else if (cvss >= 4.0) cvssSeverity = 'medium';
    }
    
    const cvssDisplay = cvss !== null ? cvss.toFixed(1) : 'N/A';
    
    // EPSS score rendering variables
    const epssVal = cve.epss || 0.0;
    const epssPercent = Math.round(epssVal * 100);
    
    let epssColorClass = 'epss-low';
    if (epssVal > 0.50) epssColorClass = 'epss-critical';
    else if (epssVal > 0.10) epssColorClass = 'epss-high';
    else if (epssVal > 0.02) epssColorClass = 'epss-medium';
    
    card.innerHTML = `
      <div class="cve-card-header">
        <span class="cve-id-badge">${cve.cve_id}</span>
        <div class="cve-badges">
          ${cve.in_kev ? '<span class="badge badge-kev">🚨 KEV</span>' : ''}
          <span class="badge badge-cvss ${cvssSeverity}">CVSS: ${cvssDisplay}</span>
        </div>
      </div>
      
      <div class="cve-target">
        Product: <strong>${cve.vendor} ${cve.product}</strong>
      </div>
      
      <div class="cve-body" title="${cve.description}">
        ${cve.description || 'No description available.'}
      </div>
      
      <div class="cve-card-footer">
        <span class="cve-date">Added: ${cve.date_added || 'Unknown'}</span>
        
        <div class="epss-telemetry">
          <span class="epss-label">${epssPercent}% Exploit</span>
          <svg viewBox="0 0 36 36" class="circular-chart">
            <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
            <path class="circle ${epssColorClass}" stroke-dasharray="${epssPercent}, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
          </svg>
        </div>
      </div>
    `;
    
    card.addEventListener('click', () => {
      openDrawer(cve);
    });
    
    return card;
  }

  // 6. Remediation Drawer Logic
  function openDrawer(cve) {
    el.drawerCveId.textContent = cve.cve_id;
    el.drawerTitle.textContent = cve.title !== 'Unknown Vulnerability' ? cve.title : `${cve.vendor} ${cve.product} Vulnerability`;
    
    // CVSS Info
    const cvssVal = cve.cvss;
    el.drawerCvssScore.textContent = cvssVal !== null ? cvssVal.toFixed(1) : 'N/A';
    el.drawerCvssVersion.textContent = `CVSS ${cve.cvss_version || 'Version'}`;
    
    // Set CVSS score class
    el.drawerCvssScore.className = 'score-value';
    if (cvssVal >= 9.0) el.drawerCvssScore.classList.add('color-critical');
    else if (cvssVal >= 7.0) el.drawerCvssScore.classList.add('color-high');
    else if (cvssVal >= 4.0) el.drawerCvssScore.classList.add('color-medium');
    else el.drawerCvssScore.classList.add('color-low');

    // EPSS Info
    const epssVal = cve.epss || 0.0;
    const epssPercent = (epssVal * 100).toFixed(2);
    const epssPercentile = cve.percentile ? Math.round(cve.percentile * 100) : 0;
    
    el.drawerEpssScore.textContent = `${epssPercent}%`;
    el.drawerEpssPercentile.textContent = `${epssPercentile}th percentile`;

    // Metadata
    el.drawerVendor.textContent = cve.vendor;
    el.drawerProduct.textContent = cve.product;
    el.drawerDateAdded.textContent = cve.date_added || 'N/A';
    
    if (cve.due_date) {
      el.drawerDueDate.textContent = cve.due_date;
      el.drawerDueDateContainer.style.display = 'flex';
    } else {
      el.drawerDueDateContainer.style.display = 'none';
    }
    
    // Ransomware Indicator
    if (cve.ransomware && cve.ransomware.toLowerCase() === 'known') {
      el.drawerRansomwareAlert.style.display = 'flex';
    } else {
      el.drawerRansomwareAlert.style.display = 'none';
    }

    // Tactical action
    const category = getTriageCategory(cve);
    el.drawerActionCallout.className = `action-callout ${category}`;
    
    let recommendationText = '';
    if (category === 'immediate') {
      recommendationText = 'Emergency patch cycle. Confirmed active threat to production infrastructure. Deploy vendor patches immediately or apply containment.';
    } else if (category === 'high') {
      recommendationText = 'High probability of weaponisation in the next 30 days. Prioritise patching in the current sprint to prevent initial access.';
    } else if (category === 'scheduled') {
      recommendationText = 'Theoretical danger, but no active exploit chatter. Schedule remediation during your standard corporate maintenance cycles.';
    } else {
      recommendationText = 'Low severity and low exploit probability. Watchlist and defer for baseline corporate hygiene.';
    }
    el.drawerTacticalAction.textContent = recommendationText;

    // Description text
    el.drawerDescription.textContent = cve.description || 'No detailed vulnerability summary is available for this CVE.';

    // Required Action
    if (cve.in_kev && cve.required_action) {
      el.drawerRequiredAction.textContent = cve.required_action;
      el.drawerRemediationSection.style.display = 'block';
    } else {
      el.drawerRequiredAction.textContent = '';
      el.drawerRemediationSection.style.display = 'none';
    }

    // Reference Links
    el.drawerReferences.innerHTML = '';
    
    // Extract reference links
    let links = [];
    if (cve.notes) {
      // Split notes if they contain urls
      links = cve.notes.split(';').map(l => l.trim()).filter(l => l.startsWith('http'));
    }
    
    if (links.length === 0) {
      // Fallback: search links in description or generate standard NVD link
      links.push(`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`);
    }
    
    links.forEach(url => {
      const li = document.createElement('li');
      const domain = new URL(url).hostname.replace('www.', '');
      li.innerHTML = `<a href="${url}" target="_blank" rel="noopener noreferrer">${domain} - Reference Bulletin &nearr;</a>`;
      el.drawerReferences.appendChild(li);
    });

    // Reset copy button status
    el.btnCopyRemediation.textContent = 'Copy Action';
    el.btnCopyRemediation.className = 'btn-copy-code';
    
    // Open drawer UI
    el.drawerBackdrop.classList.add('active');
    el.drawer.classList.add('active');
    el.drawer.setAttribute('aria-hidden', 'false');
    document.body.style.overflow = 'hidden'; // Lock background scroll
  }

  function closeDrawer() {
    el.drawerBackdrop.classList.remove('active');
    el.drawer.classList.remove('active');
    el.drawer.setAttribute('aria-hidden', 'true');
    document.body.style.overflow = 'auto'; // Unlock scroll
  }

  // 7. Event Handlers & Subscriptions
  
  // Tabs Category Filter Click
  const tabs = [el.tabAll, el.tabImmediate, el.tabHigh, el.tabScheduled, el.tabWatchlist];
  tabs.forEach(tab => {
    if (!tab) return;
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeCategory = tab.dataset.category;
      state.currentPage = 1;
      applyFilters();
    });
  });

  // Live search input
  el.searchInput.addEventListener('input', (e) => {
    state.searchQuery = e.target.value;
    state.currentPage = 1;
    applyFilters();
  });

  // CVSS Slider
  el.cvssSlider.addEventListener('input', (e) => {
    state.minCVSS = parseFloat(e.target.value);
    el.cvssVal.textContent = state.minCVSS.toFixed(1);
    state.currentPage = 1;
    applyFilters();
  });

  // EPSS Slider
  el.epssSlider.addEventListener('input', (e) => {
    state.minEPSS = parseInt(e.target.value);
    el.epssVal.textContent = state.minEPSS;
    state.currentPage = 1;
    applyFilters();
  });

  // Sort dropdown
  el.sortSelect.addEventListener('change', (e) => {
    state.sortBy = e.target.value;
    state.currentPage = 1;
    applyFilters();
  });

  // Reset Filters
  el.resetFiltersBtn.addEventListener('click', resetAllFilters);
  if (el.clearVendorFilter) {
    el.clearVendorFilter.addEventListener('click', () => {
      state.activeVendor = null;
      document.querySelectorAll('.heatmap-block').forEach(b => b.classList.remove('active-filter'));
      el.heatmapFilterIndicator.style.display = 'none';
      state.currentPage = 1;
      applyFilters();
    });
  }

  function resetAllFilters() {
    el.searchInput.value = '';
    state.searchQuery = '';
    
    el.cvssSlider.value = 0;
    state.minCVSS = 0;
    el.cvssVal.textContent = '0.0';
    
    el.epssSlider.value = 0;
    state.minEPSS = 0;
    el.epssVal.textContent = '0';
    
    el.sortSelect.value = 'cvss-desc';
    state.sortBy = 'cvss-desc';
    
    state.activeVendor = null;
    document.querySelectorAll('.heatmap-block').forEach(b => b.classList.remove('active-filter'));
    if (el.heatmapFilterIndicator) el.heatmapFilterIndicator.style.display = 'none';
    
    // Reset active tabs
    tabs.forEach(t => t.classList.remove('active'));
    el.tabAll.classList.add('active');
    state.activeCategory = 'all';
    
    state.currentPage = 1;
    applyFilters();
  }

  // Load More Button
  el.loadMoreBtn.addEventListener('click', () => {
    state.currentPage++;
    renderGrid();
  });

  // Drawer Close events
  el.closeDrawerBtn.addEventListener('click', closeDrawer);
  el.drawerBackdrop.addEventListener('click', closeDrawer);
  
  // Close drawer on ESC
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && el.drawer.classList.contains('active')) {
      closeDrawer();
    }
  });

  // Copy Action Plan to clipboard
  el.btnCopyRemediation.addEventListener('click', () => {
    const text = el.drawerRequiredAction.textContent || el.drawerTacticalAction.textContent;
    navigator.clipboard.writeText(text).then(() => {
      el.btnCopyRemediation.textContent = 'Copied!';
      el.btnCopyRemediation.classList.add('copied');
      setTimeout(() => {
        el.btnCopyRemediation.textContent = 'Copy Action';
        el.btnCopyRemediation.classList.remove('copied');
      }, 2000);
    }).catch(err => {
      console.error('Failed to copy action plan:', err);
    });
  });

  // Fire Init
  init();
});
