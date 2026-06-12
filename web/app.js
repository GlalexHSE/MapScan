function escapeHtml(text) {
  if (text === null || text === undefined) return "";
  return String(text)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function loadData() {
  fetch("/api/stats")
    .then(function (r) { return r.json(); })
    .then(function (s) {
      document.getElementById("status").textContent = "статус: онлайн";
      document.getElementById("stat-hosts").textContent = s.hosts;
      document.getElementById("stat-open").textContent = s.open_ports;
      document.getElementById("stat-findings").textContent = s.findings;
      document.getElementById("stat-scans").textContent = s.scans;
    })
    .catch(function () {
      document.getElementById("status").textContent = "статус: нет связи";
    });

  fetch("/api/services")
    .then(function (r) { return r.json(); })
    .then(function (rows) {
      var body = document.getElementById("services-body");
      if (rows.length === 0) {
        body.innerHTML = "<tr><td colspan='5'>нет данных</td></tr>";
        return;
      }
      var html = "";
      for (var i = 0; i < rows.length; i++) {
        var r = rows[i];
        html += "<tr>";
        html += "<td>" + escapeHtml(r.ip) + "</td>";
        html += "<td>" + escapeHtml(r.port) + "/" + escapeHtml(r.proto) + "</td>";
        html += "<td>" + escapeHtml(r.service) + "</td>";
        html += "<td>" + (escapeHtml(r.banner) || "-") + "</td>";
        html += "<td>" + escapeHtml(r.last_seen) + "</td>";
        html += "</tr>";
      }
      body.innerHTML = html;
    });

  fetch("/api/findings")
    .then(function (r) { return r.json(); })
    .then(function (rows) {
      var list = document.getElementById("findings-list");
      if (rows.length === 0) {
        list.innerHTML = "<li>нет данных</li>";
        return;
      }
      var html = "";
      for (var i = 0; i < rows.length; i++) {
        var f = rows[i];
        html += "<li>" + escapeHtml(f.ip) + ":" + escapeHtml(f.port) +
                "/" + escapeHtml(f.proto) + " - " + escapeHtml(f.service) +
                " (скан #" + escapeHtml(f.scan_id) + ")</li>";
      }
      list.innerHTML = html;
    });
}

function startScan() {
  var btn = document.getElementById("scan-btn");
  btn.disabled = true;
  btn.textContent = "Сканирую...";
  fetch("/api/scan", { method: "POST" })
    .then(function (r) { return r.json(); })
    .then(function (res) {
      if (res.status === "busy") {
        alert("Скан уже идёт");
      }
    })
    .catch(function () {
      alert("Ошибка запуска скана");
    });
  setTimeout(function () {
    btn.disabled = false;
    btn.textContent = "Запустить скан";
    loadData();
  }, 3000);
}

loadData();
setInterval(loadData, 8000);
