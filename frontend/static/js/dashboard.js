// Toast Notification System
function showToast(message, type = 'info') {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const toast = document.createElement("div");
  toast.className = `toast toast-${type}`;
  toast.innerHTML = `<span>${message}</span>`;
  
  container.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(100%)';
    setTimeout(() => toast.remove(), 200);
  }, 3500);
}

// Manual Mailpit Polling
async function pollNow() {
  const btn = document.getElementById("poll-btn");
  if (!btn) return;

  btn.disabled = true;
  const originalText = btn.innerHTML;
  btn.innerHTML = `⏳ Polling Mailpit...`;

  try {
    const resp = await fetch("/api/poll-now", { method: "POST" });
    const data = await resp.json();

    if (data.processed > 0) {
      showToast(`Processed ${data.processed} new email(s)`, 'success');
      setTimeout(() => window.location.reload(), 800);
    } else {
      showToast("No new emails found in Mailpit queue", 'info');
      btn.innerHTML = `✓ No New Mail`;
      setTimeout(() => {
        btn.innerHTML = originalText;
        btn.disabled = false;
      }, 1500);
    }
  } catch (err) {
    console.error(err);
    showToast("Error polling Mailpit service", 'error');
    btn.innerHTML = originalText;
    btn.disabled = false;
  }
}

// Auto Refresh Timer Toggle
let autoRefreshTimer = null;

function toggleAutoRefresh() {
  const btn = document.getElementById("auto-refresh-btn");
  const syncStatus = document.getElementById("sync-status");

  if (autoRefreshTimer) {
    clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
    btn.innerHTML = `⏱️ Auto-Sync: Off`;
    btn.classList.remove("btn-primary");
    btn.classList.add("btn-secondary");
    if (syncStatus) syncStatus.textContent = "Live Monitoring";
    showToast("Auto-sync disabled", "info");
  } else {
    autoRefreshTimer = setInterval(async () => {
      if (syncStatus) syncStatus.textContent = "Auto-syncing...";
      try {
        const resp = await fetch("/api/poll-now", { method: "POST" });
        const data = await resp.json();
        if (data.processed > 0) {
          window.location.reload();
        }
      } catch (e) {
        console.error("Auto refresh error", e);
      } finally {
        if (syncStatus) syncStatus.textContent = "Live Monitoring (Auto 10s)";
      }
    }, 10000);

    btn.innerHTML = `⏱️ Auto-Sync: ON (10s)`;
    btn.classList.remove("btn-secondary");
    if (syncStatus) syncStatus.textContent = "Live Monitoring (Auto 10s)";
    showToast("Auto-sync enabled (10s interval)", "success");
  }
}

// Client-Side Search & Tab Filtering
function setupFiltering() {
  const searchInput = document.getElementById("search-input");
  const tabBtns = document.querySelectorAll(".tab-btn");
  const tableRows = document.querySelectorAll("#email-table tbody tr:not(#no-emails-row)");

  let currentTab = "ALL";
  let searchQuery = "";

  function applyFilters() {
    let visibleCount = 0;
    tableRows.forEach((row) => {
      const classification = row.dataset.classification || "";
      const searchText = (row.dataset.search || "").toLowerCase();

      const matchesTab = (currentTab === "ALL") ||
        (currentTab === "PHISHING" && (classification === "PHISHING" || classification === "CRITICAL PHISHING")) ||
        (classification === currentTab);

      const matchesSearch = !searchQuery || searchText.includes(searchQuery);

      if (matchesTab && matchesSearch) {
        row.style.display = "";
        visibleCount++;
      } else {
        row.style.display = "none";
      }
    });
  }

  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      searchQuery = e.target.value.toLowerCase().trim();
      applyFilters();
    });
  }

  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentTab = btn.dataset.filter;
      applyFilters();
    });
  });
}

// User Restriction Toggle
async function toggleUserStatus(userEmail, btnEl) {
  if (btnEl) btnEl.disabled = true;
  try {
    const resp = await fetch("/api/users/toggle-status", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: userEmail }),
    });
    const data = await resp.json();
    if (resp.ok && data.success) {
      showToast(`User ${userEmail} is now ${data.new_status}`, 'success');
      setTimeout(() => window.location.reload(), 500);
    } else {
      showToast(data.error || "Failed to update user status", 'error');
      if (btnEl) btnEl.disabled = false;
    }
  } catch (err) {
    console.error(err);
    showToast("Network error updating user status", 'error');
    if (btnEl) btnEl.disabled = false;
  }
}

// Phishing Incident Actions
async function reportPhishing(emailId) {
  try {
    const resp = await fetch(`/api/incidents/${emailId}/report`, { method: "POST" });
    if (resp.ok) {
      showToast("Phishing incident reported and escalated to SOC", 'success');
      setTimeout(() => window.location.href = "/", 800);
    }
  } catch (err) {
    showToast("Error reporting phishing incident", 'error');
  }
}

async function deleteEmail(emailId) {
  try {
    const resp = await fetch(`/api/incidents/${emailId}/delete`, { method: "POST" });
    if (resp.ok) {
      showToast("Threat email deleted and purged from queue", 'info');
      setTimeout(() => window.location.href = "/", 800);
    }
  } catch (err) {
    showToast("Error deleting email threat", 'error');
  }
}

// DOM Initialization
document.addEventListener("DOMContentLoaded", () => {
  const pollBtn = document.getElementById("poll-btn");
  if (pollBtn) pollBtn.addEventListener("click", pollNow);

  const autoRefreshBtn = document.getElementById("auto-refresh-btn");
  if (autoRefreshBtn) autoRefreshBtn.addEventListener("click", toggleAutoRefresh);

  setupFiltering();

  document.querySelectorAll(".toggle-user-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const email = btn.dataset.userEmail;
      toggleUserStatus(email, btn);
    });
  });

  document.querySelectorAll("[data-report-id]").forEach((el) => {
    el.addEventListener("click", () => reportPhishing(el.dataset.reportId));
  });

  document.querySelectorAll("[data-delete-id]").forEach((el) => {
    el.addEventListener("click", () => deleteEmail(el.dataset.deleteId));
  });
});
