import streamlit as st
import pandas as pd
import sqlite3
from datetime import date, datetime

# ---------------- CONFIG ----------------
st.set_page_config(page_title="Receipt & Expenditure Tracker", layout="wide")

DB_FILE = "transactions.db"

HEADS = ["Head 1", "Head 2", "Head 3", "Head 4", "Head 5"]

# ---------------- DATABASE ----------------
def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def create_table():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT,
            amount REAL,
            purpose TEXT,
            head TEXT,
            type TEXT
        )
    """)
    conn.commit()
    conn.close()

def load_data():
    conn = get_connection()
    df = pd.read_sql("SELECT * FROM transactions", conn, parse_dates=["date"])
    conn.close()
    return df

def insert_record(data):
    conn = get_connection()
    conn.execute(
        "INSERT INTO transactions (date, amount, purpose, head, type) VALUES (?, ?, ?, ?, ?)",
        data
    )
    conn.commit()
    conn.close()

def update_record(record_id, data):
    conn = get_connection()
    conn.execute(
        """UPDATE transactions
           SET date=?, amount=?, purpose=?, head=?, type=?
           WHERE id=?""",
        (*data, record_id)
    )
    conn.commit()
    conn.close()

def delete_record(record_id):
    conn = get_connection()
    conn.execute("DELETE FROM transactions WHERE id=?", (record_id,))
    conn.commit()
    conn.close()

create_table()
df = load_data()

# ---------------- SIDEBAR ----------------
st.sidebar.title("📂 Navigation")
menu = st.sidebar.radio(
    "Go to",
    ["Add Record", "View / Edit / Delete", "Monthly Summary", "FY Summary"]
)

# ---------------- ADD RECORD ----------------
if menu == "Add Record":
    st.title("➕ Add Receipt / Expenditure")

    col1, col2 = st.columns(2)

    with col1:
        record_type = st.selectbox("Type", ["receipt", "expenditure"])
        head = st.selectbox("Head", HEADS)
        record_date = st.date_input("Date", value=date.today())

    with col2:
        amount = st.number_input("Amount", min_value=0.01)
        purpose = st.text_input("Purpose")

    if st.button("Save Record"):
        if purpose.strip() == "":
            st.error("Purpose cannot be empty")
        else:
            insert_record((
                record_date.isoformat(),
                amount,
                purpose,
                head,
                record_type
            ))
            st.success("Record added successfully")
            st.experimental_rerun()


# ---------------- VIEW / EDIT / DELETE ----------------
elif menu == "View / Edit / Delete":
    st.title("📋 View / Edit / Delete Records")

    head_filter = st.selectbox("Filter by Head", ["All"] + HEADS)
    type_filter = st.selectbox("Filter by Type", ["All", "receipt", "expenditure"])

    filtered_df = df.copy()

    if head_filter != "All":
        filtered_df = filtered_df[filtered_df["head"] == head_filter]

    if type_filter != "All":
        filtered_df = filtered_df[filtered_df["type"] == type_filter]

    if filtered_df.empty:
        st.info("No records found.")
    else:
        st.dataframe(filtered_df)

        record_id = st.number_input(
            "Enter Record ID to Edit/Delete",
            min_value=int(filtered_df["id"].min()),
            max_value=int(filtered_df["id"].max()),
            step=1
        )

        selected = filtered_df[filtered_df["id"] == record_id]

        if selected.empty:
            st.warning("Selected record is not available with current filters.")
            st.stop()

        record = selected.iloc[0]


        st.subheader("✏️ Edit Record")
        col1, col2 = st.columns(2)

        with col1:
            new_type = st.selectbox("Type", ["receipt", "expenditure"],
                                    index=0 if record["type"] == "receipt" else 1)
            new_head = st.selectbox("Head", HEADS,
                                    index=HEADS.index(record["head"]))
            new_date = st.date_input("Date", record["date"].date())

        with col2:
            new_amount = st.number_input("Amount", value=float(record["amount"]))
            new_purpose = st.text_input("Purpose", value=record["purpose"])

        col_u, col_d = st.columns(2)

        if col_u.button("Update Record"):
            update_record(record_id, (
                new_date.isoformat(),
                new_amount,
                new_purpose,
                new_head,
                new_type
            ))
            st.success("Record updated")
            st.experimental_rerun()


        if col_d.button("Delete Record"):
            delete_record(record_id)
            st.warning("Record deleted")
            st.experimental_rerun()


# ---------------- MONTHLY SUMMARY ----------------
elif menu == "Monthly Summary":
    st.title("📅 Monthly Summary")

    df["month"] = df["date"].dt.to_period("M")

    month = st.selectbox(
        "Select Month",
        sorted(df["month"].astype(str).unique())
    )

    month_df = df[df["month"].astype(str) == month]

    summary = month_df.groupby(["head", "type"])["amount"].sum().unstack(fill_value=0)
    summary["Remaining"] = summary.get("receipt", 0) - summary.get("expenditure", 0)

    st.dataframe(summary)

# ---------------- FINANCIAL YEAR SUMMARY ----------------
elif menu == "FY Summary":
    st.title("📆 Financial Year Summary (April–March)")

    def get_fy(d):
        return f"{d.year}-{d.year+1}" if d.month >= 4 else f"{d.year-1}-{d.year}"

    df["FY"] = df["date"].apply(get_fy)

    fy = st.selectbox("Select Financial Year", sorted(df["FY"].unique()))

    fy_df = df[df["FY"] == fy]

    summary = fy_df.groupby(["head", "type"])["amount"].sum().unstack(fill_value=0)
    summary["Remaining"] = summary.get("receipt", 0) - summary.get("expenditure", 0)

    st.dataframe(summary)
