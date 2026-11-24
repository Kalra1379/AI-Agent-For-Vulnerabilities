// Local: leave as is. After deploying the backend on Render, put its URL here.
window.API_BASE = location.hostname === "localhost" || location.hostname === "127.0.0.1"
  ? "http://localhost:8000" : "https://YOUR-BACKEND.onrender.com";
