# Streamlit App — Data Files Template

This template demonstrates a Streamlit app that reads **local CSV files** from the `data/` folder,
caches them, and renders basic charts and tables.

## Deploy (GitHub → Streamlit Cloud)
1. Push this folder as a GitHub repo.
2. On Streamlit Cloud, pick `app.py` as the entry file.
3. Done!

## Local run
```bash
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Contents
- `data/` — example CSV files
- `app.py` — main Streamlit app
- `pages/` — optional extra page (Data Dictionary)
- `.streamlit/config.toml` — server config
- `requirements.txt` — pinned libs
