import streamlit as st

st.title("📚 Data Dictionary")

st.markdown(
"""
### sales.csv
- `date` — transaction date
- `region` — sales region
- `product` — product name
- `units` — quantity sold
- `revenue` — total revenue (USD)

### inventory.csv
- `sku` — item code
- `location` — warehouse/site
- `on_hand` — units currently available
- `reorder_point` — threshold to reorder
"""
)
