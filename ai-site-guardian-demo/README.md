# AI Site Guardian: demo prototype

An AI agent that watches a (simulated) WordPress site, rates each issue by risk, auto-fixes only low-risk ones
through a safe pipeline, and escalates the rest for human approval.

## Run locally
Backend (terminal 1):
    cd backend
    python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=sk-ant-...                  # optional; Windows: set ANTHROPIC_API_KEY=...
    uvicorn main:app --reload --port 8000
Frontend (terminal 2):
    cd frontend && python -m http.server 5173
Open http://localhost:5173

## Deploy
Backend on Render: New Web Service, root directory `backend`, build `pip install -r requirements.txt`,
start `uvicorn main:app --host 0.0.0.0 --port $PORT`. Env vars: ANTHROPIC_API_KEY, ALLOWED_ORIGINS (your Vercel URL).
Frontend on Vercel: import the repo, root directory `frontend`, framework "Other". Before deploying, put your
Render URL into `frontend/config.js`.
Note: Render free tier sleeps after idle, so open the backend URL once before a live demo.

## Demo script
1. Scan site. 2. Fix low-risk issues (watch the pipeline; Slider Lite fails tests and rolls back).
3. Approve the Stripe update. 4. Simulate the Friday vulnerability, then use Virtual patch or Approve.
5. Speed up site for before/after. 6. Show the client email panel.

## Chrome extension (extension/)
1. Start the backend. 2. Chrome > chrome://extensions > turn on Developer mode > Load unpacked > pick the `extension` folder.
3. Open any website (best: a WordPress site), click the Guardian icon. If the backend is on Render, paste its URL into the
Backend field at the bottom of the popup. Tip: pin the extension to the toolbar.
