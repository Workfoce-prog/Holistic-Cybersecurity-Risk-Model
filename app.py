import streamlit as st
import pandas as pd
import numpy as np
from pathlib import Path
import plotly.express as px

st.set_page_config(page_title="Holistic Cybersecurity Risk Model", page_icon="🛡️", layout="wide")
st.title("🛡️ Holistic Cybersecurity Risk Model (CSV-only)")

DATA_DIR = Path(__file__).parent / "data"

def load_csv_safe(path: Path):
    if not path.exists():
        return pd.DataFrame()
    try:
        return pd.read_csv(path)
    except Exception as e:
        st.error(f"Failed to read {path.name}: {e}")
        return pd.DataFrame()

def load_all_sources(uploads):
    data = {}
    for name in ["file_catalog","acl","file_events","security_signals","backup_coverage","audit_config","user_baseline","phish_click_events"]:
        if uploads.get(name) is not None:
            try:
                data[name] = pd.read_csv(uploads[name])
            except Exception as e:
                st.error(f"Could not read uploaded {name}: {e}")
                data[name] = pd.DataFrame()
        else:
            data[name] = load_csv_safe(DATA_DIR / f"{name}.csv")
    return data

def ensure_types(d):
    if not d["file_catalog"].empty:
        fc = d["file_catalog"].copy()
        for c in ["created_ts","last_modified_ts"]:
            if c in fc.columns: fc[c] = pd.to_datetime(fc[c], errors="coerce")
        if "encryption_at_rest" in fc: fc["encryption_at_rest"] = fc["encryption_at_rest"].astype(bool)
        d["file_catalog"] = fc
    if not d["acl"].empty:
        a = d["acl"].copy()
        if "created_ts" in a: a["created_ts"] = pd.to_datetime(a["created_ts"], errors="coerce")
        if "is_public_link" in a: a["is_public_link"] = a["is_public_link"].astype(bool)
        d["acl"] = a
    if not d["file_events"].empty:
        fe = d["file_events"].copy()
        if "event_ts" in fe: fe["event_ts"] = pd.to_datetime(fe["event_ts"], errors="coerce")
        if "device_managed" in fe: fe["device_managed"] = fe["device_managed"].astype(bool)
        d["file_events"] = fe
    if not d["security_signals"].empty:
        ss = d["security_signals"].copy()
        if "signal_ts" in ss: ss["signal_ts"] = pd.to_datetime(ss["signal_ts"], errors="coerce")
        d["security_signals"] = ss
    if not d["backup_coverage"].empty:
        b = d["backup_coverage"].copy()
        if "last_successful_backup" in b: b["last_successful_backup"] = pd.to_datetime(b["last_successful_backup"], errors="coerce")
        d["backup_coverage"] = b
    if not d["audit_config"].empty:
        ac = d["audit_config"].copy()
        if "audit_enabled" in ac: ac["audit_enabled"] = ac["audit_enabled"].astype(bool)
        d["audit_config"] = ac
    if not d["phish_click_events"].empty:
        pc = d["phish_click_events"].copy()
        if "click_ts" in pc: pc["click_ts"] = pd.to_datetime(pc["click_ts"], errors="coerce")
        d["phish_click_events"] = pc
    return d

st.sidebar.header("Upload CSVs (optional — sample data used if empty)")
uploads = {}
for key,label in [
    ("file_catalog","file_catalog.csv"),
    ("acl","acl.csv"),
    ("file_events","file_events.csv"),
    ("security_signals","security_signals.csv"),
    ("backup_coverage","backup_coverage.csv"),
    ("audit_config","audit_config.csv"),
    ("user_baseline","user_baseline.csv (optional)"),
    ("phish_click_events","phish_click_events.csv (optional)"),
]:
    uploads[key] = st.sidebar.file_uploader(label=label, type=["csv"])

st.sidebar.header("Scoring (base severities)")
base_sev = {
    "broad_groups": st.sidebar.slider("Excessive groups/public links", 10, 100, 70),
    "stale_write_access": st.sidebar.slider("Write access but inactive", 10, 100, 60),
    "public_link_sensitive": st.sidebar.slider("Public link on sensitive", 10, 100, 80),
    "hash_mismatch": st.sidebar.slider("Hash mismatch", 10, 100, 90),
    "macro_external": st.sidebar.slider("Macro from external", 10, 100, 80),
    "unencrypted_sensitive": st.sidebar.slider("Unencrypted at rest", 10, 100, 75),
    "backup_gap": st.sidebar.slider("Backup gap", 10, 100, 65),
    "audit_disabled": st.sidebar.slider("Audit disabled/short retain", 10, 100, 60),
    "post_phish_surge": st.sidebar.slider("Post-phish download surge", 10, 100, 70),
    "retention_violation": st.sidebar.slider("Retention violation", 10, 100, 60),
    "soft_delete_sensitive": st.sidebar.slider("Soft-delete sensitive >30d", 10, 100, 55),
}
rag_red = st.sidebar.slider("RAG RED threshold", 50, 100, 80)
rag_amber = st.sidebar.slider("RAG AMBER threshold", 30, 90, 50)

data = ensure_types(load_all_sources(uploads))

with st.expander("Preview data (head)"):
    for k, v in data.items():
        st.write(f"**{k}**", v.head())

detections = []

# R1: broad access or public link
if not data["acl"].empty:
    acl = data["acl"]
    sens_files = set(data["file_catalog"][data["file_catalog"]["classification"].isin(["Confidential","Restricted"])]["file_id"]) if not data["file_catalog"].empty else set()
    for fid, grp in acl.groupby("file_id"):
        is_public = bool(grp["is_public_link"].fillna(False).any()) if "is_public_link" in grp else False
        groups = (grp["principal_type"]=="group").sum() if "principal_type" in grp else 0
        if groups > 5 or is_public:
            detections.append({"file_id": fid, "rule": "broad_groups", "base": base_sev["broad_groups"], "details": f"groups={groups}, public_link={is_public}"})
        if is_public and fid in sens_files:
            detections.append({"file_id": fid, "rule": "public_link_sensitive", "base": base_sev["public_link_sensitive"], "details": "Public link on sensitive file"})

# R2: write/owner but inactive 180d (approximate: no events at all)
if not data["acl"].empty and not data["file_events"].empty:
    writes = data["acl"][data["acl"]["access_level"].isin(["write","owner"])]
    touched = data["file_events"].groupby(["file_id","user_id"]).size().reset_index().rename(columns={0:"cnt"})
    merged = writes.merge(touched, how="left", left_on=["file_id","principal_id"], right_on=["file_id","user_id"])
    inactive = merged[merged["cnt"].isna()]
    for _,row in inactive.iterrows():
        detections.append({"file_id": row["file_id"], "rule": "stale_write_access", "base": base_sev["stale_write_access"], "details": f"user {row['principal_id']} has write/owner but no activity"})

# R5: hash mismatch
if not data["security_signals"].empty:
    mm = data["security_signals"]
    mm = mm[(mm["signal_type"]=="hash_mismatch") & (mm["signal_value"].astype(str).str.lower()=="true")]
    for fid in mm["file_id"].unique():
        detections.append({"file_id": fid, "rule": "hash_mismatch", "base": base_sev["hash_mismatch"], "details": "Hash mismatch"})

# R6: macro present + unmanaged device observed
if not data["security_signals"].empty:
    macro = data["security_signals"]
    macro = macro[(macro["signal_type"]=="macro_present") & (macro["signal_value"].astype(str).str.lower()=="true")]
    if not data["file_events"].empty and "device_managed" in data["file_events"].columns:
        um = data["file_events"].groupby("file_id")["device_managed"].apply(lambda s: (~s.fillna(True)).any()).reset_index(name="has_unmanaged")
        macro = macro.merge(um, on="file_id", how="left")
    for _,row in macro.iterrows():
        if row.get("has_unmanaged", True):
            detections.append({"file_id": row["file_id"], "rule": "macro_external", "base": base_sev["macro_external"], "details": "Macro file + unmanaged device"})

# R7: unencrypted at rest on sensitive
if not data["file_catalog"].empty and "encryption_at_rest" in data["file_catalog"]:
    unenc = data["file_catalog"]
    unenc = unenc[(~unenc["encryption_at_rest"]) & (unenc["classification"].isin(["Confidential","Restricted"]))]
    for fid in unenc["file_id"].unique():
        detections.append({"file_id": fid, "rule": "unencrypted_sensitive", "base": base_sev["unencrypted_sensitive"], "details": "Sensitive data unencrypted at rest"})

# R8: backup RPO breach mapped to files by system
if not data["backup_coverage"].empty:
    bc = data["backup_coverage"].copy()
    bc["last_successful_backup"] = pd.to_datetime(bc["last_successful_backup"], errors="coerce")
    now = pd.Timestamp.utcnow()
    bc["age_min"] = (now - bc["last_successful_backup"]).dt.total_seconds()/60.0
    breach = bc[bc["age_min"] > bc["rpo_minutes"]]
    for _,row in breach.iterrows():
        if not data["file_catalog"].empty:
            affected = data["file_catalog"][data["file_catalog"]["system"]==row["system"]]["file_id"].unique()
            for fid in affected:
                detections.append({"file_id": fid, "rule": "backup_gap", "base": base_sev["backup_gap"], "details": f"System {row['system']} RPO breach"})
        else:
            detections.append({"file_id": f"*system:{row['system']}", "rule": "backup_gap", "base": base_sev["backup_gap"], "details": "RPO breach"})

# R9: audit disabled / retention < 90 -> map to files by system
if not data["audit_config"].empty:
    bad = data["audit_config"][(~data["audit_config"]["audit_enabled"]) | (data["audit_config"]["retention_days"] < 90)]
    for _,row in bad.iterrows():
        if not data["file_catalog"].empty:
            affected = data["file_catalog"][data["file_catalog"]["system"]==row["system"]]["file_id"].unique()
            for fid in affected:
                detections.append({"file_id": fid, "rule": "audit_disabled", "base": base_sev["audit_disabled"], "details": f"audit_enabled={row['audit_enabled']}, retention={row['retention_days']}"})
# R10: post-phish surge (downloads > 3*p95 in 48h window)
if (not data["phish_click_events"].empty) and (not data["file_events"].empty):
    ub = data["user_baseline"]
    for _,evt in data["phish_click_events"].iterrows():
        u = evt["user_id"]; t0 = evt["click_ts"]; t1 = t0 + pd.Timedelta(hours=48)
        window = data["file_events"][(data["file_events"]["user_id"]==u) & (data["file_events"]["event_ts"]>=t0) & (data["file_events"]["event_ts"]<=t1) & (data["file_events"]["event_type"]=="download")]
        if not window.empty:
            dl = len(window)
            p95 = float(ub.loc[ub["user_id"]==u, "weekly_download_p95"].iloc[0]) if (not ub.empty and (ub["user_id"]==u).any()) else 3.0
            if dl > 3 * p95:
                for fid in window["file_id"].unique():
                    detections.append({"file_id": fid, "rule": "post_phish_surge", "base": base_sev["post_phish_surge"], "details": f"user={u} downloads={dl} > 3*p95({p95})"})

# R12: retention violation
if not data["file_catalog"].empty and "retention_days_exceeded" in data["file_catalog"]:
    viol = data["file_catalog"][data["file_catalog"]["retention_days_exceeded"]==True]
    for fid in viol["file_id"].unique():
        detections.append({"file_id": fid, "rule": "retention_violation", "base": base_sev["retention_violation"], "details": "Retention exceeded"})

# R13: soft-delete > 30d on sensitive
if not data["file_catalog"].empty and {"deleted_soft","days_deleted","classification"}.issubset(set(data["file_catalog"].columns)):
    sd = data["file_catalog"]
    bad = sd[(sd["deleted_soft"]==True) & (sd["days_deleted"]>=30) & (sd["classification"].isin(["Confidential","Restricted"]))]
    for fid in bad["file_id"].unique():
        detections.append({"file_id": fid, "rule": "soft_delete_sensitive", "base": base_sev["soft_delete_sensitive"], "details": "Sensitive soft-deleted > 30d"})

det_df = pd.DataFrame(detections)

# Scoring
file_scores = pd.DataFrame(columns=["file_id","score","RAG"])
if not det_df.empty:
    cls_map = data["file_catalog"][["file_id","classification"]].drop_duplicates() if not data["file_catalog"].empty else pd.DataFrame(columns=["file_id","classification"])
    det_df = det_df.merge(cls_map, on="file_id", how="left")
    det_df["sens_mult"] = det_df["classification"].map({"Public":0.5,"Internal":1.0,"Confidential":1.3,"Restricted":1.6}).fillna(1.0)
    det_df["ctx_mult"] = 1.0
    det_df["score_i"] = (det_df["base"] * det_df["sens_mult"] * det_df["ctx_mult"]).clip(upper=100)
    agg = det_df.groupby("file_id")["score_i"].apply(lambda s: 1 - np.prod(1 - s/100.0))
    file_scores = agg.reset_index().rename(columns={"score_i":"score"})
    file_scores["score"] = (file_scores["score"]*100).round(1)

def rag_label(x, r=80, a=50):
    if x >= r: return "Red"
    if x >= a: return "Amber"
    return "Green"

if not file_scores.empty:
    file_scores["RAG"] = file_scores["score"].apply(lambda x: rag_label(x, r=rag_red, a=rag_amber))

user_scores = pd.DataFrame(columns=["user_id","score"])
if not file_scores.empty and not data["acl"].empty:
    owners = data["acl"][data["acl"]["access_level"].isin(["write","owner"])][["file_id","principal_id"]].rename(columns={"principal_id":"user_id"})
    us = owners.merge(file_scores, on="file_id", how="left")
    user_scores = us.groupby("user_id")["score"].mean().reset_index().sort_values("score", ascending=False)

tabs = st.tabs(["Upload & Preview","Detections","Risk Scores","Dashboards","Downloads","About"])

with tabs[0]:
    st.subheader("Upload or use sample CSVs")
    st.write("If you don’t upload files, the app uses the sample data in `/data`.")
    for k,v in data.items():
        with st.expander(f"{k}.csv preview", expanded=False):
            st.dataframe(v.head(20), use_container_width=True)

with tabs[1]:
    st.subheader("Detections")
    if det_df.empty:
        st.info("No detections yet. Provide data or use the sample CSVs in `/data`.")
    else:
        st.dataframe(det_df[["file_id","rule","base","classification","score_i","details"]].sort_values("score_i", ascending=False), use_container_width=True)

with tabs[2]:
    st.subheader("Risk scores")
    if file_scores.empty:
        st.info("No scores computed yet.")
    else:
        c1,c2 = st.columns([2,1])
        with c1:
            st.markdown("**Top risky files**")
            st.dataframe(file_scores.sort_values("score", ascending=False).head(50), use_container_width=True)
        with c2:
            st.markdown("**RAG distribution**")
            rag_counts = file_scores["RAG"].value_counts().reset_index()
            rag_counts.columns = ["RAG","count"]
            if not rag_counts.empty:
                fig = px.pie(rag_counts, names="RAG", values="count", hole=0.4)
                st.plotly_chart(fig, use_container_width=True)
        st.markdown("**User roll-up**")
        st.dataframe(user_scores.head(50), use_container_width=True)

with tabs[3]:
    st.subheader("Dashboards")
    if det_df.empty or file_scores.empty:
        st.info("Need detections & scores to render dashboards.")
    else:
        c1,c2 = st.columns(2)
        with c1:
            top_rules = det_df["rule"].value_counts().reset_index()
            top_rules.columns = ["rule","count"]
            st.markdown("**Detections by rule**")
            st.bar_chart(top_rules.set_index("rule"))
        with c2:
            if "classification" in det_df.columns:
                cls = det_df.groupby("classification").size().reset_index(name="count")
                st.markdown("**Detections by classification**")
                st.bar_chart(cls.set_index("classification"))
        st.markdown("**Public links on sensitive files**")
        if not data["acl"].empty and not data["file_catalog"].empty and "is_public_link" in data["acl"]:
            pub = data["acl"][data["acl"]["is_public_link"]==True].merge(data["file_catalog"][["file_id","classification"]], on="file_id", how="left")
            st.dataframe(pub, use_container_width=True)

with tabs[4]:
    st.subheader("Download results")
    if not det_df.empty:
        st.download_button("Download detections CSV", det_df.to_csv(index=False), "detections.csv", "text/csv")
    if not file_scores.empty:
        st.download_button("Download file scores CSV", file_scores.to_csv(index=False), "file_scores.csv", "text/csv")
    if not user_scores.empty:
        st.download_button("Download user scores CSV", user_scores.to_csv(index=False), "user_scores.csv", "text/csv")

with tabs[5]:
    st.subheader("About")
    st.markdown(\"\"\"
**What this app does**  
- Ingests CSVs (or uses sample data) for file/ACL/events/security/backup/audit.
- Runs deterministic detection rules.
- Computes risk scores with sensitivity multipliers and shows RAG.
- Provides dashboards and CSV exports.

**Why CSV-only?**  
- Keeps deployments simple and avoids PyArrow build issues on some Python versions.

**Next steps**  
- Add enterprise-specific rules, SOAR actions, and direct SIEM connectors.
\"\"\")
