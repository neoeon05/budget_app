import streamlit as st
import pandas as pd
import sqlite3
from datetime import date, datetime, timedelta
import hashlib
import secrets
import json
import io
import shutil
import os
from pathlib import Path

# --- MUST BE THE VERY FIRST STREAMLIT COMMAND ---
st.set_page_config(page_title="Receipt & Expenditure Tracker", layout="wide", page_icon="💰")

# Try to import optional dependencies
try:
    import plotly.express as px
    import plotly.graph_objects as go
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    # Warning removed to prevent "set_page_config" conflict

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import inch
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ---------------- CONFIG ----------------

DB_FILE = "transactions.db"
BACKUP_DIR = "backups"
HEADS = ["Head 1", "Head 2", "Head 3", "Head 4", "Head 5"]

# Create backup directory safely
os.makedirs(BACKUP_DIR, exist_ok=True)

# ---------------- SECURITY FUNCTIONS ----------------
def hash_password(password, salt=None):
    """Hash password with salt using SHA-256"""
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return pwd_hash, salt

def verify_password(password, stored_hash, salt):
    """Verify password against stored hash"""
    pwd_hash, _ = hash_password(password, salt)
    return pwd_hash == stored_hash

# ---------------- DATABASE ----------------
def get_connection():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def create_tables():
    conn = get_connection()
    
    # Users table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            full_name TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    """)
    
    # Transactions table with audit fields
    conn.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT,
            amount REAL,
            purpose TEXT,
            head TEXT,
            type TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            modified_at TEXT,
            modified_by INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (created_by) REFERENCES users (id),
            FOREIGN KEY (modified_by) REFERENCES users (id)
        )
    """)
    
    # Audit trail table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_trail (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id INTEGER,
            user_id INTEGER,
            action TEXT,
            old_data TEXT,
            new_data TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES transactions (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    # Budget limits table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS budget_limits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            head TEXT,
            monthly_limit REAL,
            yearly_limit REAL,
            alert_threshold REAL DEFAULT 80.0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            UNIQUE(user_id, head)
        )
    """)
    
    # Saved filter presets table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS filter_presets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            preset_name TEXT,
            filter_config TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)
    
    conn.commit()
    
    # Create default admin user if no users exist
    cursor = conn.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        pwd_hash, salt = hash_password("admin123")
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, full_name, role) VALUES (?, ?, ?, ?, ?)",
            ("admin", pwd_hash, salt, "Administrator", "admin")
        )
        conn.commit()
    
    conn.close()

def backup_database():
    """Create a backup of the database"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = os.path.join(BACKUP_DIR, f"transactions_backup_{timestamp}.db")
    shutil.copy2(DB_FILE, backup_file)
    return backup_file

def authenticate_user(username, password):
    """Authenticate user and return user data if successful"""
    conn = get_connection()
    cursor = conn.execute(
        "SELECT id, username, password_hash, salt, full_name, role FROM users WHERE username = ?",
        (username,)
    )
    user = cursor.fetchone()
    conn.close()
    
    if user and verify_password(password, user[2], user[3]):
        return {
            'id': user[0],
            'username': user[1],
            'full_name': user[4],
            'role': user[5]
        }
    return None

def update_last_login(user_id):
    """Update last login timestamp"""
    conn = get_connection()
    conn.execute(
        "UPDATE users SET last_login = ? WHERE id = ?",
        (datetime.now().isoformat(), user_id)
    )
    conn.commit()
    conn.close()

def create_user(username, password, full_name, email, role='user'):
    """Create a new user"""
    conn = get_connection()
    try:
        pwd_hash, salt = hash_password(password)
        conn.execute(
            "INSERT INTO users (username, password_hash, salt, full_name, email, role) VALUES (?, ?, ?, ?, ?, ?)",
            (username, pwd_hash, salt, full_name, email, role)
        )
        conn.commit()
        conn.close()
        return True, "User created successfully"
    except sqlite3.IntegrityError:
        conn.close()
        return False, "Username already exists"
    except Exception as e:
        conn.close()
        return False, f"Error: {str(e)}"

def load_data(user_id, is_admin=False, filters=None):
    """Load transactions with optional filters"""
    conn = get_connection()
    
    base_query = """
        SELECT t.*, u.username, 
               c.username as created_by_name,
               m.username as modified_by_name
        FROM transactions t 
        LEFT JOIN users u ON t.user_id = u.id 
        LEFT JOIN users c ON t.created_by = c.id
        LEFT JOIN users m ON t.modified_by = m.id
    """
    
    conditions = []
    params = []
    
    if not is_admin:
        conditions.append("t.user_id = ?")
        params.append(user_id)
    
    if filters:
        if filters.get('head') and filters['head'] != 'All':
            conditions.append("t.head = ?")
            params.append(filters['head'])
        
        if filters.get('type') and filters['type'] != 'All':
            conditions.append("t.type = ?")
            params.append(filters['type'])
        
        if filters.get('user') and filters['user'] != 'All':
            conditions.append("u.username = ?")
            params.append(filters['user'])
        
        if filters.get('date_from'):
            conditions.append("t.date >= ?")
            params.append(filters['date_from'])
        
        if filters.get('date_to'):
            conditions.append("t.date <= ?")
            params.append(filters['date_to'])
        
        if filters.get('search'):
            conditions.append("t.purpose LIKE ?")
            params.append(f"%{filters['search']}%")
        
        if filters.get('min_amount'):
            conditions.append("t.amount >= ?")
            params.append(filters['min_amount'])
        
        if filters.get('max_amount'):
            conditions.append("t.amount <= ?")
            params.append(filters['max_amount'])
    
    if conditions:
        base_query += " WHERE " + " AND ".join(conditions)
    
    base_query += " ORDER BY t.date DESC"
    
    df = pd.read_sql(base_query, conn, params=params, parse_dates=["date"])
    conn.close()
    return df

def load_all_users():
    """Load all users"""
    conn = get_connection()
    df = pd.read_sql("SELECT id, username, full_name, email, role, created_at, last_login FROM users", conn)
    conn.close()
    return df

def insert_record(user_id, data, created_by):
    """Insert record with audit trail"""
    conn = get_connection()
    cursor = conn.execute(
        "INSERT INTO transactions (user_id, date, amount, purpose, head, type, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (user_id, *data, created_by)
    )
    transaction_id = cursor.lastrowid
    
    # Audit trail
    conn.execute(
        "INSERT INTO audit_trail (transaction_id, user_id, action, new_data) VALUES (?, ?, ?, ?)",
        (transaction_id, created_by, "CREATE", json.dumps({
            'date': data[0], 'amount': data[1], 'purpose': data[2], 
            'head': data[3], 'type': data[4]
        }))
    )
    
    conn.commit()
    conn.close()

def update_record(record_id, user_id, data, is_admin=False, modified_by=None):
    """Update record with audit trail"""
    conn = get_connection()
    
    # Get old data
    old_data = conn.execute("SELECT date, amount, purpose, head, type FROM transactions WHERE id=?", 
                           (record_id,)).fetchone()
    
    if is_admin:
        conn.execute(
            """UPDATE transactions
               SET date=?, amount=?, purpose=?, head=?, type=?, modified_at=?, modified_by=?
               WHERE id=?""",
            (*data, datetime.now().isoformat(), modified_by, record_id)
        )
    else:
        conn.execute(
            """UPDATE transactions
               SET date=?, amount=?, purpose=?, head=?, type=?, modified_at=?, modified_by=?
               WHERE id=? AND user_id=?""",
            (*data, datetime.now().isoformat(), modified_by, record_id, user_id)
        )
    
    # Audit trail
    conn.execute(
        "INSERT INTO audit_trail (transaction_id, user_id, action, old_data, new_data) VALUES (?, ?, ?, ?, ?)",
        (record_id, modified_by, "UPDATE", 
         json.dumps(dict(zip(['date', 'amount', 'purpose', 'head', 'type'], old_data))),
         json.dumps({'date': data[0], 'amount': data[1], 'purpose': data[2], 
                    'head': data[3], 'type': data[4]}))
    )
    
    conn.commit()
    conn.close()

def delete_record(record_id, user_id, is_admin=False, deleted_by=None):
    """Delete record with audit trail"""
    conn = get_connection()
    
    # Get data before deletion
    old_data = conn.execute("SELECT date, amount, purpose, head, type FROM transactions WHERE id=?", 
                           (record_id,)).fetchone()
    
    if is_admin:
        conn.execute("DELETE FROM transactions WHERE id=?", (record_id,))
    else:
        conn.execute("DELETE FROM transactions WHERE id=? AND user_id=?", (record_id, user_id))
    
    # Audit trail
    conn.execute(
        "INSERT INTO audit_trail (transaction_id, user_id, action, old_data) VALUES (?, ?, ?, ?)",
        (record_id, deleted_by, "DELETE", 
         json.dumps(dict(zip(['date', 'amount', 'purpose', 'head', 'type'], old_data))))
    )
    
    conn.commit()
    conn.close()

def get_audit_trail(transaction_id=None, user_id=None, limit=100):
    """Get audit trail records"""
    conn = get_connection()
    query = """
        SELECT a.*, u.username, t.purpose
        FROM audit_trail a
        LEFT JOIN users u ON a.user_id = u.id
        LEFT JOIN transactions t ON a.transaction_id = t.id
        WHERE 1=1
    """
    params = []
    
    if transaction_id:
        query += " AND a.transaction_id = ?"
        params.append(transaction_id)
    
    if user_id:
        query += " AND a.user_id = ?"
        params.append(user_id)
    
    query += " ORDER BY a.timestamp DESC LIMIT ?"
    params.append(limit)
    
    df = pd.read_sql(query, conn, params=params)
    conn.close()
    return df

def delete_user(user_id):
    """Delete user and all their data"""
    conn = get_connection()
    conn.execute("DELETE FROM transactions WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM budget_limits WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM filter_presets WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM audit_trail WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()

def change_password(user_id, new_password):
    """Change user password"""
    conn = get_connection()
    pwd_hash, salt = hash_password(new_password)
    conn.execute(
        "UPDATE users SET password_hash=?, salt=? WHERE id=?",
        (pwd_hash, salt, user_id)
    )
    conn.commit()
    conn.close()

# ---------------- BUDGET MANAGEMENT ----------------
def set_budget_limit(user_id, head, monthly_limit, yearly_limit, alert_threshold):
    """Set budget limit for a head"""
    conn = get_connection()
    try:
        conn.execute(
            """INSERT OR REPLACE INTO budget_limits 
               (user_id, head, monthly_limit, yearly_limit, alert_threshold) 
               VALUES (?, ?, ?, ?, ?)""",
            (user_id, head, monthly_limit, yearly_limit, alert_threshold)
        )
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.close()
        return False

def get_budget_limits(user_id):
    """Get budget limits for user"""
    conn = get_connection()
    df = pd.read_sql("SELECT * FROM budget_limits WHERE user_id = ?", conn, params=(user_id,))
    conn.close()
    return df

def check_budget_alerts(user_id, df):
    """Check for budget alerts"""
    alerts = []
    budgets = get_budget_limits(user_id)
    
    if budgets.empty:
        return alerts
    
    current_month = datetime.now().strftime("%Y-%m")
    current_year = datetime.now().year
    
    for _, budget in budgets.iterrows():
        head = budget['head']
        
        # Check monthly budget
        if budget['monthly_limit'] > 0:
            monthly_expenses = df[
                (df['head'] == head) & 
                (df['type'] == 'expenditure') & 
                (df['date'].dt.strftime("%Y-%m") == current_month)
            ]['amount'].sum()
            
            percentage = (monthly_expenses / budget['monthly_limit']) * 100
            
            if percentage >= budget['alert_threshold']:
                alerts.append({
                    'type': 'monthly',
                    'head': head,
                    'spent': monthly_expenses,
                    'limit': budget['monthly_limit'],
                    'percentage': percentage
                })
        
        # Check yearly budget
        if budget['yearly_limit'] > 0:
            yearly_expenses = df[
                (df['head'] == head) & 
                (df['type'] == 'expenditure') & 
                (df['date'].dt.year == current_year)
            ]['amount'].sum()
            
            percentage = (yearly_expenses / budget['yearly_limit']) * 100
            
            if percentage >= budget['alert_threshold']:
                alerts.append({
                    'type': 'yearly',
                    'head': head,
                    'spent': yearly_expenses,
                    'limit': budget['yearly_limit'],
                    'percentage': percentage
                })
    
    return alerts

# ---------------- FILTER PRESETS ----------------
def save_filter_preset(user_id, preset_name, filter_config):
    """Save filter preset"""
    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO filter_presets (user_id, preset_name, filter_config) VALUES (?, ?, ?)",
            (user_id, preset_name, json.dumps(filter_config))
        )
        conn.commit()
        conn.close()
        return True
    except:
        conn.close()
        return False

def get_filter_presets(user_id):
    """Get user's filter presets"""
    conn = get_connection()
    df = pd.read_sql("SELECT * FROM filter_presets WHERE user_id = ?", conn, params=(user_id,))
    conn.close()
    return df

def delete_filter_preset(preset_id):
    """Delete filter preset"""
    conn = get_connection()
    conn.execute("DELETE FROM filter_presets WHERE id = ?", (preset_id,))
    conn.commit()
    conn.close()

# ---------------- EXPORT FUNCTIONS ----------------
def export_to_csv(df):
    """Export dataframe to CSV"""
    return df.to_csv(index=False).encode('utf-8')

def export_to_excel(df):
    """Export dataframe to Excel"""
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Transactions', index=False)
        
        # Add summary sheet
        summary = df.groupby(['head', 'type'])['amount'].sum().unstack(fill_value=0)
        summary['Remaining'] = summary.get('receipt', 0) - summary.get('expenditure', 0)
        summary.to_excel(writer, sheet_name='Summary')
    
    return output.getvalue()

def generate_pdf_report(df, title="Transaction Report"):
    """Generate PDF report"""
    if not REPORTLAB_AVAILABLE:
        return None
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#1f77b4'))
    elements.append(Paragraph(title, title_style))
    elements.append(Spacer(1, 0.3*inch))
    
    # Summary statistics
    total_receipts = df[df['type'] == 'receipt']['amount'].sum()
    total_expenses = df[df['type'] == 'expenditure']['amount'].sum()
    balance = total_receipts - total_expenses
    
    summary_text = f"""
    <b>Report Summary</b><br/>
    Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}<br/>
    Total Transactions: {len(df)}<br/>
    Total Receipts: ₹{total_receipts:,.2f}<br/>
    Total Expenditure: ₹{total_expenses:,.2f}<br/>
    Net Balance: ₹{balance:,.2f}
    """
    elements.append(Paragraph(summary_text, styles['Normal']))
    elements.append(Spacer(1, 0.3*inch))
    
    # Transaction table
    table_data = [['Date', 'Type', 'Head', 'Amount', 'Purpose']]
    for _, row in df.head(50).iterrows():  # Limit to 50 rows for PDF
        table_data.append([
            row['date'].strftime("%Y-%m-%d") if pd.notna(row['date']) else '',
            row['type'],
            row['head'],
            f"₹{row['amount']:,.2f}",
            row['purpose'][:30] + '...' if len(str(row['purpose'])) > 30 else str(row['purpose'])
        ])
    
    table = Table(table_data, colWidths=[1.2*inch, 1*inch, 1*inch, 1.2*inch, 2.6*inch])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    elements.append(table)
    doc.build(elements)
    
    return buffer.getvalue()

# ---------------- ANALYTICS ----------------
def create_pie_chart(df, title):
    """Create pie chart for head-wise spending"""
    if not PLOTLY_AVAILABLE:
        return None
    
    head_totals = df[df['type'] == 'expenditure'].groupby('head')['amount'].sum()
    
    fig = px.pie(
        values=head_totals.values,
        names=head_totals.index,
        title=title,
        hole=0.3
    )
    fig.update_traces(textposition='inside', textinfo='percent+label')
    return fig

def create_trend_chart(df, title):
    """Create line chart for spending trends"""
    if not PLOTLY_AVAILABLE:
        return None
    
    df['month'] = df['date'].dt.to_period('M').astype(str)
    monthly = df.groupby(['month', 'type'])['amount'].sum().unstack(fill_value=0)
    
    # Ensure both columns exist, filling with 0.0 if missing
    if 'receipt' not in monthly.columns:
        monthly['receipt'] = 0.0
    if 'expenditure' not in monthly.columns:
        monthly['expenditure'] = 0.0
    
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=monthly.index, y=monthly['receipt'], 
                             mode='lines+markers', name='Receipts', line=dict(color='green')))
    fig.add_trace(go.Scatter(x=monthly.index, y=monthly['expenditure'], 
                             mode='lines+markers', name='Expenditure', line=dict(color='red')))
    
    fig.update_layout(title=title, xaxis_title='Month', yaxis_title='Amount (₹)')
    return fig

def create_budget_vs_actual_chart(df, budgets, head):
    """Create budget vs actual comparison chart"""
    if not PLOTLY_AVAILABLE or budgets.empty:
        return None
    
    current_month = datetime.now().strftime("%Y-%m")
    actual = df[(df['head'] == head) & (df['type'] == 'expenditure') & 
                (df['date'].dt.strftime("%Y-%m") == current_month)]['amount'].sum()
    
    budget_row = budgets[budgets['head'] == head]
    if budget_row.empty:
        return None
    
    budget = budget_row.iloc[0]['monthly_limit']
    
    fig = go.Figure()
    fig.add_trace(go.Bar(x=[head], y=[budget], name='Budget', marker_color='lightblue'))
    fig.add_trace(go.Bar(x=[head], y=[actual], name='Actual', marker_color='red' if actual > budget else 'green'))
    
    fig.update_layout(title=f'Budget vs Actual - {head}', yaxis_title='Amount (₹)', barmode='group')
    return fig

# ---------------- INITIALIZE ----------------
create_tables()

# ---------------- SESSION STATE ----------------
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'user' not in st.session_state:
    st.session_state.user = None

# ---------------- LOGIN PAGE ----------------
def login_page():
    st.title("🔐 Login to Budget Tracker")
    st.markdown("---")
    
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                submit = st.form_submit_button("Login")
                
                if submit:
                    if username and password:
                        user = authenticate_user(username, password)
                        if user:
                            st.session_state.logged_in = True
                            st.session_state.user = user
                            update_last_login(user['id'])
                            st.success(f"Welcome, {user['full_name']}!")
                            st.rerun()  # UPDATED FOR STREAMLIT CLOUD
                        else:
                            st.error("Invalid username or password")
                    else:
                        st.error("Please enter both username and password")
        
        with tab2:
            with st.form("register_form"):
                new_username = st.text_input("Username", key="reg_username")
                new_password = st.text_input("Password", type="password", key="reg_password")
                confirm_password = st.text_input("Confirm Password", type="password")
                full_name = st.text_input("Full Name")
                email = st.text_input("Email")
                
                register = st.form_submit_button("Register")
                
                if register:
                    if not all([new_username, new_password, confirm_password, full_name]):
                        st.error("Please fill all required fields")
                    elif new_password != confirm_password:
                        st.error("Passwords do not match")
                    elif len(new_password) < 6:
                        st.error("Password must be at least 6 characters")
                    else:
                        success, message = create_user(new_username, new_password, full_name, email)
                        if success:
                            st.success(message + " - Please login now")
                        else:
                            st.error(message)
        
        st.info("**Default Admin Credentials:**\nUsername: `admin` | Password: `admin123`")

# ---------------- MAIN APP ----------------
def main_app():
    is_admin = st.session_state.user['role'] == 'admin'
    
    # Sidebar with user info
    st.sidebar.title("📂 Navigation")
    st.sidebar.markdown(f"**Logged in as:** {st.session_state.user['full_name']}")
    st.sidebar.markdown(f"**Role:** {st.session_state.user['role'].title()}")
    
    if is_admin:
        st.sidebar.success("👑 Admin Access")
    
    # Menu options
    menu_options = [
        "📊 Dashboard",
        "➕ Add Record", 
        "📋 View / Edit / Delete",
        "📅 Monthly Summary", 
        "📆 FY Summary",
        "📈 Analytics",
        "💰 Budget Management",
        "📥 Import/Export",
        "🔍 Audit Trail",
        "👤 Profile"
    ]
    
    if is_admin:
        menu_options.append("👥 User Management")
    
    menu = st.sidebar.radio("Go to", menu_options)
    
    # --- CLOUD PERSISTENCE HELPER ---
    st.sidebar.markdown("---")
    st.sidebar.markdown("### ☁️ Cloud Storage")
    if os.path.exists(DB_FILE):
        with open(DB_FILE, "rb") as fp:
            st.sidebar.download_button(
                label="📥 Download Database",
                data=fp,
                file_name=f"transactions_backup_{datetime.now().strftime('%Y%m%d')}.db",
                mime="application/x-sqlite3",
                help="Streamlit Cloud resets data on reboot. Download this to save your work!"
            )
    # --------------------------------
    
    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.user = None
        st.rerun()  # UPDATED FOR STREAMLIT CLOUD
    
    # Load data
    df = load_data(st.session_state.user['id'], is_admin)
    
    # Check for budget alerts
    if not df.empty:
        alerts = check_budget_alerts(st.session_state.user['id'], df)
        if alerts:
            with st.sidebar:
                st.warning(f"⚠️ {len(alerts)} Budget Alert(s)")
    
    # ---------------- DASHBOARD ----------------
    if menu == "📊 Dashboard":
        st.title("📊 Dashboard Overview")
        
        if df.empty:
            st.info("No transactions yet. Add your first transaction to get started!")
        else:
            # Key metrics
            col1, col2, col3, col4 = st.columns(4)
            
            total_receipts = df[df['type'] == 'receipt']['amount'].sum()
            total_expenses = df[df['type'] == 'expenditure']['amount'].sum()
            balance = total_receipts - total_expenses
            
            with col1:
                st.metric("💰 Total Receipts", f"₹{total_receipts:,.2f}")
            with col2:
                st.metric("💸 Total Expenditure", f"₹{total_expenses:,.2f}")
            with col3:
                delta_color = "normal" if balance >= 0 else "inverse"
                st.metric("📊 Net Balance", f"₹{balance:,.2f}", 
                         delta=f"₹{abs(balance):,.2f}", delta_color=delta_color)
            with col4:
                st.metric("📝 Total Transactions", len(df))
            
            # Budget alerts
            alerts = check_budget_alerts(st.session_state.user['id'], df)
            if alerts:
                st.subheader("⚠️ Budget Alerts")
                for alert in alerts:
                    percentage = alert['percentage']
                    alert_type = "🔴" if percentage >= 100 else "🟡"
                    st.warning(
                        f"{alert_type} **{alert['head']}** ({alert['type'].title()}): "
                        f"₹{alert['spent']:,.2f} / ₹{alert['limit']:,.2f} ({percentage:.1f}%)"
                    )
            
            # Recent transactions
            st.subheader("📝 Recent Transactions")
            recent_cols = ['date', 'type', 'head', 'amount', 'purpose']
            if is_admin:
                recent_cols.insert(1, 'username')
            st.dataframe(df[recent_cols].head(10))
            
            # Quick charts
            if PLOTLY_AVAILABLE:
                col1, col2 = st.columns(2)
                
                with col1:
                    pie_fig = create_pie_chart(df, "Expenditure by Head")
                    if pie_fig:
                        st.plotly_chart(pie_fig)
                
                with col2:
                    trend_fig = create_trend_chart(df, "Monthly Trends")
                    if trend_fig:
                        st.plotly_chart(trend_fig)
    
    # ---------------- ADD RECORD ----------------
    elif menu == "➕ Add Record":
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
                insert_record(
                    st.session_state.user['id'],
                    (record_date.isoformat(), amount, purpose, head, record_type),
                    st.session_state.user['id']
                )
                st.success("✅ Record added successfully")
                st.rerun() # UPDATED

    # ---------------- VIEW / EDIT / DELETE ----------------
    elif menu == "📋 View / Edit / Delete":
        st.title("📋 View / Edit / Delete Records")
        
        if is_admin:
            st.info("👑 Admin Mode: Viewing all users' transactions")

        # Advanced Filters
        with st.expander("🔍 Advanced Filters", expanded=True):
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                head_filter = st.selectbox("Head", ["All"] + HEADS)
                type_filter = st.selectbox("Type", ["All", "receipt", "expenditure"])
            
            with col2:
                date_from = st.date_input("From Date", value=None)
                date_to = st.date_input("To Date", value=None)
            
            with col3:
                search_purpose = st.text_input("Search Purpose")
                min_amount = st.number_input("Min Amount", min_value=0.0, value=0.0)
            
            with col4:
                max_amount = st.number_input("Max Amount", min_value=0.0, value=0.0)
                if is_admin:
                    user_list = df['username'].unique().tolist() if 'username' in df.columns else []
                    user_filter = st.selectbox("User", ["All"] + user_list)
            
            # Save/Load Filter Presets
            col1, col2 = st.columns(2)
            with col1:
                preset_name = st.text_input("Preset Name")
                if st.button("💾 Save Filter Preset"):
                    if preset_name:
                        filter_config = {
                            'head': head_filter,
                            'type': type_filter,
                            'date_from': date_from.isoformat() if date_from else None,
                            'date_to': date_to.isoformat() if date_to else None,
                            'search': search_purpose,
                            'min_amount': min_amount if min_amount > 0 else None,
                            'max_amount': max_amount if max_amount > 0 else None
                        }
                        if save_filter_preset(st.session_state.user['id'], preset_name, filter_config):
                            st.success("Preset saved!")
                        else:
                            st.error("Failed to save preset")
            
            with col2:
                presets = get_filter_presets(st.session_state.user['id'])
                if not presets.empty:
                    preset_choice = st.selectbox("Load Preset", [""] + presets['preset_name'].tolist())
                    if preset_choice and st.button("📂 Load Preset"):
                        st.rerun() # UPDATED

        # Apply filters
        filters = {
            'head': head_filter,
            'type': type_filter,
            'date_from': date_from.isoformat() if date_from else None,
            'date_to': date_to.isoformat() if date_to else None,
            'search': search_purpose if search_purpose else None,
            'min_amount': min_amount if min_amount > 0 else None,
            'max_amount': max_amount if max_amount > 0 else None,
        }
        
        if is_admin and user_filter != "All":
            filters['user'] = user_filter
        
        filtered_df = load_data(st.session_state.user['id'], is_admin, filters)

        if filtered_df.empty:
            st.info("No records found with current filters.")
        else:
            # Display with sorting
            display_cols = ['id', 'date', 'amount', 'purpose', 'head', 'type']
            if is_admin:
                display_cols.insert(1, 'username')
            
            st.dataframe(
                filtered_df[display_cols].sort_values('date', ascending=False),
            )
            
            st.download_button(
                "📥 Download as CSV",
                export_to_csv(filtered_df[display_cols]),
                "transactions.csv",
                "text/csv"
            )

            # Edit/Delete section
            st.subheader("✏️ Edit / Delete Record")
            record_id = st.number_input(
                "Enter Record ID",
                min_value=int(filtered_df["id"].min()),
                max_value=int(filtered_df["id"].max()),
                step=1
            )

            selected = filtered_df[filtered_df["id"] == record_id]

            if not selected.empty:
                record = selected.iloc[0]
                
                if is_admin and 'username' in record:
                    st.info(f"📝 Editing record from user: **{record['username']}**")

                col1, col2 = st.columns(2)

                with col1:
                    new_type = st.selectbox("Type", ["receipt", "expenditure"],
                                            index=0 if record["type"] == "receipt" else 1, key="edit_type")
                    new_head = st.selectbox("Head", HEADS,
                                            index=HEADS.index(record["head"]), key="edit_head")
                    new_date = st.date_input("Date", record["date"].date(), key="edit_date")

                with col2:
                    new_amount = st.number_input("Amount", value=float(record["amount"]), key="edit_amount")
                    new_purpose = st.text_input("Purpose", value=record["purpose"], key="edit_purpose")

                col_u, col_d = st.columns(2)

                if col_u.button("✅ Update Record"):
                    update_record(
                        record_id,
                        st.session_state.user['id'],
                        (new_date.isoformat(), new_amount, new_purpose, new_head, new_type),
                        is_admin,
                        st.session_state.user['id']
                    )
                    st.success("Record updated")
                    st.rerun() # UPDATED

                if col_d.button("🗑️ Delete Record"):
                    delete_record(record_id, st.session_state.user['id'], is_admin, st.session_state.user['id'])
                    st.warning("Record deleted")
                    st.rerun() # UPDATED

    # ---------------- MONTHLY SUMMARY ----------------
    elif menu == "📅 Monthly Summary":
        st.title("📅 Monthly Summary")
        
        if is_admin:
            st.info("👑 Admin Mode: Viewing all users' data")
            user_list = df['username'].unique().tolist() if 'username' in df.columns and not df.empty else []
            user_filter_summary = st.selectbox("View for:", ["All Users"] + user_list)
            
            if user_filter_summary != "All Users":
                df = df[df['username'] == user_filter_summary]

        if df.empty:
            st.info("No transactions found.")
        else:
            df["month"] = df["date"].dt.to_period("M")

            month = st.selectbox(
                "Select Month",
                sorted(df["month"].astype(str).unique(), reverse=True)
            )

            month_df = df[df["month"].astype(str) == month]

            summary = month_df.groupby(["head", "type"])["amount"].sum().unstack(fill_value=0)
            summary["Remaining"] = summary.get("receipt", 0) - summary.get("expenditure", 0)

            st.dataframe(summary)
            
            # Metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Receipts", f"₹{month_df[month_df['type']=='receipt']['amount'].sum():,.2f}")
            with col2:
                st.metric("Total Expenditure", f"₹{month_df[month_df['type']=='expenditure']['amount'].sum():,.2f}")
            with col3:
                balance = month_df[month_df['type']=='receipt']['amount'].sum() - month_df[month_df['type']=='expenditure']['amount'].sum()
                st.metric("Net Balance", f"₹{balance:,.2f}")
            
            # Export options
            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    "📥 Export to CSV",
                    export_to_csv(month_df),
                    f"monthly_summary_{month}.csv",
                    "text/csv"
                )
            with col2:
                excel_data = export_to_excel(month_df)
                st.download_button(
                    "📊 Export to Excel",
                    excel_data,
                    f"monthly_summary_{month}.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                )

    # ---------------- FY SUMMARY ----------------
    elif menu == "📆 FY Summary":
        st.title("📆 Financial Year Summary (April–March)")
        
        if is_admin:
            st.info("👑 Admin Mode: Viewing all users' data")
            user_list = df['username'].unique().tolist() if 'username' in df.columns and not df.empty else []
            user_filter_fy = st.selectbox("View for:", ["All Users"] + user_list)
            
            if user_filter_fy != "All Users":
                df = df[df['username'] == user_filter_fy]

        if df.empty:
            st.info("No transactions found.")
        else:
            def get_fy(d):
                return f"{d.year}-{d.year+1}" if d.month >= 4 else f"{d.year-1}-{d.year}"

            df["FY"] = df["date"].apply(get_fy)

            fy = st.selectbox("Select Financial Year", sorted(df["FY"].unique(), reverse=True))

            fy_df = df[df["FY"] == fy]

            summary = fy_df.groupby(["head", "type"])["amount"].sum().unstack(fill_value=0)
            summary["Remaining"] = summary.get("receipt", 0) - summary.get("expenditure", 0)

            st.dataframe(summary)
            
            # Metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Receipts", f"₹{fy_df[fy_df['type']=='receipt']['amount'].sum():,.2f}")
            with col2:
                st.metric("Total Expenditure", f"₹{fy_df[fy_df['type']=='expenditure']['amount'].sum():,.2f}")
            with col3:
                balance = fy_df[fy_df['type']=='receipt']['amount'].sum() - fy_df[fy_df['type']=='expenditure']['amount'].sum()
                st.metric("Net Balance", f"₹{balance:,.2f}")
            
            # Year-over-year comparison
            if PLOTLY_AVAILABLE and len(df["FY"].unique()) > 1:
                st.subheader("📊 Year-over-Year Comparison")
                yoy_data = df.groupby(['FY', 'type'])['amount'].sum().unstack(fill_value=0)
                
                fig = go.Figure()
                fig.add_trace(go.Bar(x=yoy_data.index, y=yoy_data.get('receipt', 0), name='Receipts'))
                fig.add_trace(go.Bar(x=yoy_data.index, y=yoy_data.get('expenditure', 0), name='Expenditure'))
                fig.update_layout(title='Year-over-Year Comparison', barmode='group')
                st.plotly_chart(fig)

    # ---------------- ANALYTICS ----------------
    elif menu == "📈 Analytics":
        st.title("📈 Advanced Analytics")
        
        if df.empty:
            st.info("No data available for analytics")
        else:
            tab1, tab2, tab3, tab4 = st.tabs(["📊 Charts", "📈 Trends", "💰 Budget Analysis", "🔮 Forecasting"])
            
            with tab1:
                if PLOTLY_AVAILABLE:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.subheader("Expenditure by Head")
                        pie_fig = create_pie_chart(df, "Expenditure Distribution")
                        if pie_fig:
                            st.plotly_chart(pie_fig)
                    
                    with col2:
                        st.subheader("Receipt vs Expenditure by Head")
                        head_summary = df.groupby(['head', 'type'])['amount'].sum().unstack(fill_value=0)
                        
                        fig = go.Figure()
                        fig.add_trace(go.Bar(x=head_summary.index, y=head_summary.get('receipt', 0), name='Receipts'))
                        fig.add_trace(go.Bar(x=head_summary.index, y=head_summary.get('expenditure', 0), name='Expenditure'))
                        fig.update_layout(barmode='group')
                        st.plotly_chart(fig)
                else:
                    st.warning("Install plotly for interactive charts: pip install plotly")
            
            with tab2:
                if PLOTLY_AVAILABLE:
                    st.subheader("Monthly Trends")
                    trend_fig = create_trend_chart(df, "Monthly Receipt vs Expenditure")
                    if trend_fig:
                        st.plotly_chart(trend_fig)
                    
                    # Daily average spending
                    st.subheader("Average Daily Spending")
                    df['day_of_week'] = df['date'].dt.day_name()
                    daily_avg = df[df['type']=='expenditure'].groupby('day_of_week')['amount'].mean()
                    
                    fig = px.bar(x=daily_avg.index, y=daily_avg.values, 
                                labels={'x': 'Day', 'y': 'Average Amount'})
                    st.plotly_chart(fig)
            
            with tab3:
                st.subheader("Budget vs Actual Analysis")
                budgets = get_budget_limits(st.session_state.user['id'])
                
                if budgets.empty:
                    st.info("No budgets set. Go to Budget Management to set budgets.")
                else:
                    for _, budget in budgets.iterrows():
                        if PLOTLY_AVAILABLE:
                            budget_fig = create_budget_vs_actual_chart(df, budgets, budget['head'])
                            if budget_fig:
                                st.plotly_chart(budget_fig)
            
            with tab4:
                st.subheader("🔮 Spending Forecast")
                
                # Simple linear forecast based on last 3 months
                last_3_months = df[df['date'] >= (datetime.now() - timedelta(days=90))]
                if not last_3_months.empty:
                    monthly_avg = last_3_months[last_3_months['type']=='expenditure'].groupby(
                        last_3_months['date'].dt.to_period('M')
                    )['amount'].sum().mean()
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Average Monthly Expenditure (Last 3 months)", f"₹{monthly_avg:,.2f}")
                    with col2:
                        st.metric("Projected Next Month", f"₹{monthly_avg:,.2f}")
                    
                    st.info("💡 This is a simple forecast based on your last 3 months average spending.")
                else:
                    st.info("Not enough data for forecasting. Add more transactions.")

    # ---------------- BUDGET MANAGEMENT ----------------
    elif menu == "💰 Budget Management":
        st.title("💰 Budget Management")
        
        tab1, tab2 = st.tabs(["Set Budgets", "View Budgets"])
        
        with tab1:
            st.subheader("Set Budget Limits")
            
            with st.form("budget_form"):
                col1, col2 = st.columns(2)
                
                with col1:
                    budget_head = st.selectbox("Head", HEADS)
                    monthly_limit = st.number_input("Monthly Limit (₹)", min_value=0.0, step=1000.0)
                
                with col2:
                    yearly_limit = st.number_input("Yearly Limit (₹)", min_value=0.0, step=10000.0)
                    alert_threshold = st.slider("Alert Threshold (%)", min_value=50, max_value=100, value=80)
                
                if st.form_submit_button("💾 Save Budget"):
                    if set_budget_limit(st.session_state.user['id'], budget_head, 
                                       monthly_limit, yearly_limit, alert_threshold):
                        st.success("Budget saved successfully!")
                        st.rerun() # UPDATED
                    else:
                        st.error("Failed to save budget")
        
        with tab2:
            budgets = get_budget_limits(st.session_state.user['id'])
            
            if budgets.empty:
                st.info("No budgets set yet")
            else:
                st.dataframe(budgets[['head', 'monthly_limit', 'yearly_limit', 'alert_threshold']])
                
                # Current status
                st.subheader("Current Budget Status")
                current_month = datetime.now().strftime("%Y-%m")
                
                for _, budget in budgets.iterrows():
                    head = budget['head']
                    
                    if budget['monthly_limit'] > 0:
                        spent = df[(df['head']==head) & (df['type']=='expenditure') & 
                                  (df['date'].dt.strftime("%Y-%m")==current_month)]['amount'].sum()
                        
                        percentage = (spent / budget['monthly_limit']) * 100
                        
                        col1, col2, col3 = st.columns([2, 1, 1])
                        with col1:
                            st.write(f"**{head}** (Monthly)")
                        with col2:
                            st.write(f"₹{spent:,.2f} / ₹{budget['monthly_limit']:,.2f}")
                        with col3:
                            if percentage >= 100:
                                st.error(f"{percentage:.1f}%")
                            elif percentage >= budget['alert_threshold']:
                                st.warning(f"{percentage:.1f}%")
                            else:
                                st.success(f"{percentage:.1f}%")
                        
                        st.progress(min(percentage / 100, 1.0))

    # ---------------- IMPORT/EXPORT ----------------
    elif menu == "📥 Import/Export":
        st.title("📥 Import / Export Data")
        
        tab1, tab2, tab3 = st.tabs(["Export", "Import", "Backup"])
        
        with tab1:
            st.subheader("Export Transactions")
            
            col1, col2 = st.columns(2)
            
            with col1:
                export_format = st.selectbox("Format", ["CSV", "Excel", "PDF"])
                
                # Date range for export
                export_from = st.date_input("From Date", value=None, key="export_from")
                export_to = st.date_input("To Date", value=None, key="export_to")
            
            with col2:
                export_head = st.selectbox("Head Filter", ["All"] + HEADS, key="export_head")
                export_type = st.selectbox("Type Filter", ["All", "receipt", "expenditure"], key="export_type")
            
            if st.button("Generate Export"):
                export_filters = {}
                if export_head != "All":
                    export_filters['head'] = export_head
                if export_type != "All":
                    export_filters['type'] = export_type
                if export_from:
                    export_filters['date_from'] = export_from.isoformat()
                if export_to:
                    export_filters['date_to'] = export_to.isoformat()
                
                export_df = load_data(st.session_state.user['id'], is_admin, export_filters)
                
                if export_format == "CSV":
                    st.download_button(
                        "📥 Download CSV",
                        export_to_csv(export_df),
                        f"transactions_{datetime.now().strftime('%Y%m%d')}.csv",
                        "text/csv"
                    )
                elif export_format == "Excel":
                    st.download_button(
                        "📊 Download Excel",
                        export_to_excel(export_df),
                        f"transactions_{datetime.now().strftime('%Y%m%d')}.xlsx",
                        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                    )
                elif export_format == "PDF":
                    if REPORTLAB_AVAILABLE:
                        pdf_data = generate_pdf_report(export_df, "Transaction Report")
                        if pdf_data:
                            st.download_button(
                                "📄 Download PDF",
                                pdf_data,
                                f"report_{datetime.now().strftime('%Y%m%d')}.pdf",
                                "application/pdf"
                            )
                    else:
                        st.error("Install reportlab for PDF export: pip install reportlab")
        
        with tab2:
            st.subheader("Import Transactions")
            st.info("Upload a CSV file with columns: date, amount, purpose, head, type")
            
            uploaded_file = st.file_uploader("Choose CSV file", type=['csv'])
            
            if uploaded_file:
                try:
                    import_df = pd.read_csv(uploaded_file)
                    
                    # Validate columns
                    required_cols = ['date', 'amount', 'purpose', 'head', 'type']
                    if not all(col in import_df.columns for col in required_cols):
                        st.error(f"CSV must contain columns: {', '.join(required_cols)}")
                    else:
                        st.dataframe(import_df.head())
                        
                        if st.button("Import Records"):
                            conn = get_connection()
                            imported = 0
                            for _, row in import_df.iterrows():
                                try:
                                    insert_record(
                                        st.session_state.user['id'],
                                        (row['date'], row['amount'], row['purpose'], 
                                         row['head'], row['type']),
                                        st.session_state.user['id']
                                    )
                                    imported += 1
                                except Exception as e:
                                    st.error(f"Error importing row: {e}")
                            
                            st.success(f"Successfully imported {imported} records!")
                            st.rerun() # UPDATED
                except Exception as e:
                    st.error(f"Error reading file: {e}")
        
        with tab3:
            st.subheader("Database Backup")
            st.info("Note: On Streamlit Cloud, file system is temporary. Please use the Download button in sidebar to save your data locally.")
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.button("🔒 Create Backup Now"):
                    backup_file = backup_database()
                    st.success(f"Backup created: {backup_file}")
            
            # List existing backups
            if os.path.exists(BACKUP_DIR):
                backup_files = sorted(Path(BACKUP_DIR).glob("*.db"), reverse=True)
                if backup_files:
                    st.subheader("Available Backups")
                    for backup in backup_files[:5]:
                        st.text(backup.name)

    # ---------------- AUDIT TRAIL ----------------
    elif menu == "🔍 Audit Trail":
        st.title("🔍 Audit Trail")
        
        if is_admin:
            view_all = st.checkbox("View all users' audit trail", value=False)
            audit_user_id = None if view_all else st.session_state.user['id']
        else:
            audit_user_id = st.session_state.user['id']
        
        audit_df = get_audit_trail(user_id=audit_user_id, limit=200)
        
        if audit_df.empty:
            st.info("No audit records found")
        else:
            # Filters
            col1, col2 = st.columns(2)
            with col1:
                action_filter = st.selectbox("Action", ["All", "CREATE", "UPDATE", "DELETE"])
            with col2:
                limit = st.slider("Records to show", 10, 200, 50)
            
            filtered_audit = audit_df.copy()
            if action_filter != "All":
                filtered_audit = filtered_audit[filtered_audit['action'] == action_filter]
            
            filtered_audit = filtered_audit.head(limit)
            
            # Display audit records
            for _, record in filtered_audit.iterrows():
                with st.expander(f"🕒 {record['timestamp']} - {record['action']} by {record['username']}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if record['old_data']:
                            st.write("**Old Data:**")
                            old_data = json.loads(record['old_data'])
                            st.json(old_data)
                    
                    with col2:
                        if record['new_data']:
                            st.write("**New Data:**")
                            new_data = json.loads(record['new_data'])
                            st.json(new_data)
                    
                    if record['purpose']:
                        st.write(f"**Purpose:** {record['purpose']}")

    # ---------------- PROFILE ----------------
    elif menu == "👤 Profile":
        st.title("👤 User Profile")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Account Information")
            st.write(f"**Username:** {st.session_state.user['username']}")
            st.write(f"**Full Name:** {st.session_state.user['full_name']}")
            st.write(f"**Role:** {st.session_state.user['role'].title()}")
            
            # User statistics
            user_df = load_data(st.session_state.user['id'], is_admin=False)
            st.write(f"**Total Transactions:** {len(user_df)}")
            if not user_df.empty:
                st.write(f"**Total Receipts:** ₹{user_df[user_df['type']=='receipt']['amount'].sum():,.2f}")
                st.write(f"**Total Expenditure:** ₹{user_df[user_df['type']=='expenditure']['amount'].sum():,.2f}")
        
        with col2:
            st.subheader("Change Password")
            with st.form("change_password_form"):
                new_pwd = st.text_input("New Password", type="password")
                confirm_pwd = st.text_input("Confirm New Password", type="password")
                change_btn = st.form_submit_button("Change Password")
                
                if change_btn:
                    if not new_pwd or not confirm_pwd:
                        st.error("Please fill both fields")
                    elif new_pwd != confirm_pwd:
                        st.error("Passwords do not match")
                    elif len(new_pwd) < 6:
                        st.error("Password must be at least 6 characters")
                    else:
                        change_password(st.session_state.user['id'], new_pwd)
                        st.success("Password changed successfully!")

    # ---------------- USER MANAGEMENT (Admin Only) ----------------
    elif menu == "👥 User Management":
        st.title("👥 User Management")
        
        users_df = load_all_users()
        st.dataframe(users_df)
        
        tab1, tab2 = st.tabs(["Create User", "Delete User"])
        
        with tab1:
            st.subheader("Create New User")
            with st.form("admin_create_user"):
                col1, col2 = st.columns(2)
                with col1:
                    admin_username = st.text_input("Username")
                    admin_password = st.text_input("Password", type="password")
                    admin_full_name = st.text_input("Full Name")
                with col2:
                    admin_email = st.text_input("Email")
                    admin_role = st.selectbox("Role", ["user", "admin"])
                
                create_btn = st.form_submit_button("Create User")
                
                if create_btn:
                    if all([admin_username, admin_password, admin_full_name]):
                        success, message = create_user(
                            admin_username, admin_password, admin_full_name, admin_email, admin_role
                        )
                        if success:
                            st.success(message)
                            st.rerun() # UPDATED
                        else:
                            st.error(message)
                    else:
                        st.error("Please fill all required fields")
        
        with tab2:
            st.subheader("Delete User")
            user_to_delete = st.selectbox(
                "Select User to Delete",
                users_df[users_df['id'] != st.session_state.user['id']]['username'].tolist()
            )
            
            st.warning("⚠️ This will delete the user and ALL their data permanently!")
            
            if st.button("Delete User"):
                user_id = users_df[users_df['username'] == user_to_delete]['id'].iloc[0]
                delete_user(user_id)
                st.success(f"User '{user_to_delete}' deleted successfully")
                st.rerun() # UPDATED

# ---------------- MAIN ----------------
if not st.session_state.logged_in:
    login_page()
else:
    main_app()