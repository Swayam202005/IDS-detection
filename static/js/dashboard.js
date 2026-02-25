// dashboard.js — Dashboard live updates, risk meter, charts

(function () {
  "use strict";

  // ── Read initial chart data ───────────────────────────────────────────────
  var COLORS = ["#00c8ff","#ff3a5c","#00e87a","#ffb800","#9d6eff","#ff6b35","#00bfff","#e87aff"];
  var labels, data;
  try {
    labels = JSON.parse(document.getElementById("chartLabels").textContent || "[]");
    data   = JSON.parse(document.getElementById("chartData").textContent   || "[]");
  } catch(e) { labels = []; data = []; }

  // ── Pie chart ─────────────────────────────────────────────────────────────
  var pieCtx = document.getElementById("attackPieChart");
  var pieChart = null;

  if (pieCtx) {
    Chart.defaults.color = "#4a6070";
    Chart.defaults.font.family = "'JetBrains Mono', monospace";

    pieChart = new Chart(pieCtx, {
      type: "doughnut",
      data: {
        labels: labels.length ? labels : ["No Data"],
        datasets: [{
          data:            data.length ? data : [1],
          backgroundColor: COLORS.slice(0, Math.max(labels.length, 1)).map(c => c + "bb"),
          borderColor:     COLORS.slice(0, Math.max(labels.length, 1)),
          borderWidth: 2,
          hoverOffset: 8,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: "62%",
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: "#4a6070", font: { size: 10 }, padding: 10, usePointStyle: true }
          },
          tooltip: {
            backgroundColor: "#0d1520",
            borderColor: "#1e2f3f",
            borderWidth: 1,
            titleColor: "#00c8ff",
            bodyColor:  "#d0e4f0",
          }
        }
      }
    });
  }

  // ── Risk Meter ─────────────────────────────────────────────────────────────
  function updateRiskMeter(d) {
    var last   = d.last_risk || 0;
    var arc    = document.getElementById("riskArcFill");
    var numEl  = document.getElementById("riskNumSvg");
    var lblEl  = document.getElementById("riskLabelSvg");
    var updated= document.getElementById("riskUpdated");
    var lastTypEl = document.getElementById("lastDetType");
    var lastRskEl = document.getElementById("lastDetRisk");

    if (!arc) return;

    // Arc: full = 251, offset controls fill (0 = full, 251 = empty)
    var offset = 251 - (last / 100) * 251;
    var color  = last >= 70 ? "#ff3a5c" : (last >= 40 ? "#ffb800" : "#00e87a");
    var label  = last >= 70 ? "HIGH RISK" : (last >= 40 ? "MEDIUM" : "SAFE");

    arc.style.strokeDashoffset = offset;
    arc.setAttribute("stroke", color);
    if (numEl) { numEl.textContent = last; numEl.setAttribute("fill", color); }
    if (lblEl) { lblEl.textContent = label; lblEl.setAttribute("fill", color); }
    if (updated) updated.textContent = new Date().toLocaleTimeString("en-US", {hour12: false});

    // Bars
    var highBar = document.getElementById("highBar");
    var medBar  = document.getElementById("medBar");
    var lowBar  = document.getElementById("lowBar");
    var highPct = document.getElementById("highPct");
    var medPct  = document.getElementById("medPct");
    var lowPct  = document.getElementById("lowPct");

    if (highBar) highBar.style.width  = (d.high_pct   || 0) + "%";
    if (medBar)  medBar.style.width   = (d.medium_pct || 0) + "%";
    if (lowBar)  lowBar.style.width   = (d.low_pct    || 0) + "%";
    if (highPct) highPct.textContent  = (d.high_pct   || 0) + "%";
    if (medPct)  medPct.textContent   = (d.medium_pct || 0) + "%";
    if (lowPct)  lowPct.textContent   = (d.low_pct    || 0) + "%";

    if (lastTypEl) lastTypEl.textContent = d.last_type || "—";
    if (lastRskEl) lastRskEl.textContent  = "Score: " + last + "/100";
  }

  // ── Live table ─────────────────────────────────────────────────────────────
  function classColor(cls) {
    if (cls === "Attack")     return "badge-attack";
    if (cls === "Suspicious") return "badge-suspicious";
    return "badge-normal";
  }

  function riskClass(score) {
    if (score >= 70) return "high";
    if (score >= 40) return "medium";
    return "low";
  }

  function buildRow(log) {
    return "<tr>" +
      "<td>" + (log.source_ip || "—") + "</td>" +
      "<td>" + (log.dest_ip   || "—") + "</td>" +
      "<td>" + (log.attack_type || "—") + "</td>" +
      "<td><span class='badge-ids " + classColor(log.classification) + "'>" + log.classification + "</span></td>" +
      "<td><span class='badge-ids badge-" + riskClass(log.risk_score) + "'>" + log.risk_score + "%</span></td>" +
      "</tr>";
  }

  var lastId = 0;

  function pollFeed() {
    fetch("/api/live-feed")
      .then(function(r) { return r.json(); })
      .then(function(d) {
        var tbody = document.getElementById("liveTableBody");
        var logs  = d.logs || [];
        if (!tbody || logs.length === 0) return;

        var newLogs = logs.filter(function(l) { return l.id > lastId; });
        if (newLogs.length === 0) return;

        lastId = logs[0].id;
        tbody.innerHTML = logs.map(buildRow).join("");

        // Update stat cards
        fetch("/api/risk-summary")
          .then(function(r2) { return r2.json(); })
          .then(function(rd) {
            var el;
            el = document.getElementById("statTotal");   if(el) el.textContent = rd.total;
            el = document.getElementById("statAttacks"); if(el) el.textContent = rd.high;
            updateRiskMeter(rd);

            // Update pie chart
            if (pieChart) {
              fetch("/api/live-feed")
                .then(function(r3) { return r3.json(); })
                .catch(function() {});
            }
          }).catch(function() {});
      }).catch(function() {});
  }

  // ── Engine controls (admin) ───────────────────────────────────────────────
  window.startEngine = function() {
    var token = document.querySelector("meta[name='csrf-token']");
    fetch("/api/engine/start", {
      method: "POST",
      headers: { "X-CSRFToken": token ? token.content : "" }
    }).then(function() {
      document.getElementById("btnStart").style.display  = "none";
      document.getElementById("btnStop").style.display   = "";
      var st = document.getElementById("engineStatus");
      if (st) { st.textContent = "ACTIVE"; st.className = "badge-ids badge-normal"; }
    }).catch(function() {});
  };

  window.stopEngine = function() {
    var token = document.querySelector("meta[name='csrf-token']");
    fetch("/api/engine/stop", {
      method: "POST",
      headers: { "X-CSRFToken": token ? token.content : "" }
    }).then(function() {
      document.getElementById("btnStop").style.display   = "none";
      document.getElementById("btnStart").style.display  = "";
      var st = document.getElementById("engineStatus");
      if (st) { st.textContent = "STOPPED"; st.className = "badge-ids badge-attack"; }
    }).catch(function() {});
  };

  // ── Initial + polling ─────────────────────────────────────────────────────
  fetch("/api/risk-summary")
    .then(function(r) { return r.json(); })
    .then(updateRiskMeter)
    .catch(function() {});

  setInterval(pollFeed, 4000);
  setTimeout(pollFeed,  1000);

}());
