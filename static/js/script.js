// Client-side polling for the async recon job, plus a small UX guard on
// the optional port-scan authorization checkbox.
document.addEventListener("DOMContentLoaded", () => {
  const form = document.querySelector(".scan-form");
  if (form) {
    form.addEventListener("submit", () => {
      const btn = form.querySelector(".btn-scan");
      if (btn) {
        btn.disabled = true;
        btn.textContent = "Starting…";
      }
    });
  }

  const portScanCheckbox = document.getElementById("port_scan");
  const authBox = document.getElementById("authorize-box");
  const authInput = document.getElementById("authorize_confirm");
  if (portScanCheckbox && authBox) {
    portScanCheckbox.addEventListener("change", () => {
      authBox.style.display = portScanCheckbox.checked ? "block" : "none";
      if (!portScanCheckbox.checked && authInput) authInput.value = "";
    });
  }

  const progressEl = document.getElementById("scan-progress");
  if (progressEl) {
    const jobId = progressEl.dataset.jobId;
    const poll = async () => {
      try {
        const resp = await fetch(`/scan/${jobId}/status`);
        const data = await resp.json();
        const pct = data.modules_total
          ? Math.round((data.modules_complete / data.modules_total) * 100)
          : 0;
        const fill = document.getElementById("progress-fill");
        const label = document.getElementById("progress-label");
        if (fill) fill.style.width = pct + "%";
        if (label) label.textContent = `${data.modules_complete}/${data.modules_total} modules complete`;

        if (data.status === "complete") {
          window.location.href = `/scan/${jobId}/report`;
        } else if (data.status === "error") {
          const errEl = document.getElementById("progress-error");
          if (errEl) {
            errEl.textContent = data.error || "Scan failed.";
            errEl.style.display = "block";
          }
        } else {
          setTimeout(poll, 1200);
        }
      } catch (e) {
        setTimeout(poll, 2000);
      }
    };
    poll();
  }
});
