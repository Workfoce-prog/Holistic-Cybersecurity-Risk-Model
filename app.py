import streamlit as st
import pandas as pd
from pathlib import Path

st.set_page_config(page_title="Data Files App", page_icon="📊", layout="wide")
st.title("📊 Data Files App — Local CSVs")

DATA_DIR = Path(__file__).parent / "data"

@st.cache_data
def load_csv(name: str):
    p = DATA_DIR / name
    df = pd.read_csv(p)
    return df

files = ["sales.csv", "inventory.csv"]
file_choice = st.selectbox("Choose a dataset", files)
df = load_csv(file_choice)
st.success(f"Loaded {file_choice} ({len(df):,} rows)")

st.subheader("Preview")
st.dataframe(df.head(50), use_container_width=True)

num_cols = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c])]
cat_cols = [c for c in df.columns if c not in num_cols]

if num_cols:
    st.subheader("Quick chart")
    x = st.selectbox("X (category/date)", cat_cols or df.columns, index=0)
    y = st.selectbox("Y (numeric)", num_cols, index=0)
    st.line_chart(df.groupby(x)[y].sum())

st.download_button("Download CSV", df.to_csv(index=False), file_name=file_choice, mime="text/csv")

st.sidebar.header("About")
st.sidebar.info("This template loads CSVs from the `data/` folder and caches them for speed.")
