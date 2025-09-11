// === options.js — unified API key storage for VT, MISP, EDL ===

// ---- Helpers to read/write VT input field ----
function getVTInputEl() {
  return (
    document.getElementById("virustotal_apiKey") ||
    document.getElementById("vtKey") // fallback if old HTML remains
  );
}

function readVTFromForm() {
  const el = getVTInputEl();
  return el ? el.value.trim() : "";
}

function writeVTToForm(value) {
  const el = getVTInputEl();
  if (el) el.value = value || "";
}

// ---- Save Handler ----
document.getElementById("saveBtn").addEventListener("click", () => {
  const toStore = {
    virustotal_apiKey: readVTFromForm(),
    misp_apiKey: document.getElementById("mispKey")?.value.trim() || "",
    edl_apiKey: document.getElementById("edlKey")?.value.trim() || "",
    dnsdb_apiKey: document.getElementById("dnsdbKey")?.value.trim() || "",
    otx_apiKey: document.getElementById("otxKey")?.value.trim() || "",
    umbrella_apiKey: document.getElementById("umbrella_apiKey")?.value.trim() || "",
    umbrella_apiSecret: document.getElementById("umbrella_apiSecret")?.value.trim() || "",
    userFirstName: document.getElementById("userFirstName")?.value || "",
    userLastName: document.getElementById("userLastName")?.value || "",
    userOrg: document.getElementById("userOrg")?.value || "",
    userEmail: document.getElementById("userEmail")?.value || ""
  };

  chrome.storage.local.set(toStore, () => {
    const status = document.getElementById("status");
    if (status) {
      status.textContent = "Saved.";
      setTimeout(() => (status.textContent = ""), 2000);
    }
  });
});

// ---- Load saved data on page load ----
document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get(
    [
      "virustotal_apiKey",
      "misp_apiKey",
      "edl_apiKey",
      "otx_apiKey",
      "dnsdb_apiKey",
      "umbrella_apiKey",  
      "umbrella_apiSecret",  
      "userFirstName",
      "userLastName",
      "userOrg",
      "userEmail"
    ],
    (data) => {
      if (data.virustotal_apiKey) writeVTToForm(data.virustotal_apiKey);
      if (data.misp_apiKey) document.getElementById("mispKey").value = data.misp_apiKey;
      if (data.edl_apiKey) document.getElementById("edlKey").value = data.edl_apiKey;
      if (data.dnsdb_apiKey) document.getElementById("dnsdbKey").value = data.dnsdb_apiKey;
      if (data.otx_apiKey) document.getElementById("otxKey").value = data.otx_apiKey;
      if (data.umbrella_apiKey) document.getElementById("umbrella_apiKey").value = data.umbrella_apiKey;
      if (data.umbrella_apiSecret) document.getElementById("umbrella_apiSecret").value = data.umbrella_apiSecret;

      if (data.userFirstName) document.getElementById("userFirstName").value = data.userFirstName;
      if (data.userLastName) document.getElementById("userLastName").value = data.userLastName;
      if (data.userOrg) document.getElementById("userOrg").value = data.userOrg;
      if (data.userEmail) document.getElementById("userEmail").value = data.userEmail;
    }
  );
});
