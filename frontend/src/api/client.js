// Central API client for the dashboard — point this at your FastAPI backend.
const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export async function fetchScanResults() {
  const res = await fetch(`${BASE_URL}/api/scan-results`);
  return res.json();
}

// TODO: add fetchDastResults, fetchNetworkStatus, fetchIncidentReports
