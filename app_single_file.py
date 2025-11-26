import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import time
import json
import hashlib
import random
import sqlite3
from contextlib import contextmanager
import base64
from cryptography.fernet import Fernet

# Page configuration
st.set_page_config(
    page_title="Blockchain Network Config Monitor",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for professional look
st.markdown("""
<style>
    .main-header {
        font-size: 2.8rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 1rem;
        font-weight: 700;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #2e86ab;
        margin: 1.5rem 0 1rem 0;
        font-weight: 600;
    }
    .violation-alert {
        background: linear-gradient(135deg, #ff6b6b, #ee5a52);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 6px solid #ff0000;
        margin: 1rem 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .success-box {
        background: linear-gradient(135deg, #56ab2f, #a8e6cf);
        color: white;
        padding: 1.5rem;
        border-radius: 10px;
        border-left: 6px solid #00ff00;
        margin: 1rem 0;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 10px;
        border: 1px solid #e0e0e0;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        text-align: center;
    }
    .blockchain-block {
        background: #f8f9fa;
        border: 2px solid #dee2e6;
        border-radius: 8px;
        padding: 1rem;
        margin: 0.5rem 0;
        font-family: monospace;
    }
    .stButton button {
        width: 100%;
    }
</style>
""", unsafe_allow_html=True)

class DatabaseManager:
    def __init__(self):
        self.init_database()
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect('network_monitor.db', check_same_thread=False)
        try:
            yield conn
        finally:
            conn.close()
    
    def init_database(self):
        with self.get_connection() as conn:
            # Devices table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE,
                    ip_address TEXT,
                    device_type TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Configurations table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS configurations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    config_hash TEXT,
                    config_text TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_name) REFERENCES devices (name)
                )
            ''')
            
            # Violations table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_name TEXT,
                    expected_hash TEXT,
                    actual_hash TEXT,
                    severity TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (device_name) REFERENCES devices (name)
                )
            ''')
            
            # Blockchain table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS blockchain (
                    block_index INTEGER PRIMARY KEY,
                    previous_hash TEXT,
                    block_hash TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    data TEXT
                )
            ''')
            
            # Insert default devices if none exist
            cursor = conn.execute('SELECT COUNT(*) FROM devices')
            if cursor.fetchone()[0] == 0:
                default_devices = [
                    ('core-router-1', '192.168.1.1', 'router'),
                    ('access-switch-1', '192.168.1.2', 'switch'),
                    ('firewall-1', '192.168.1.3', 'firewall')
                ]
                conn.executemany('''
                    INSERT INTO devices (name, ip_address, device_type)
                    VALUES (?, ?, ?)
                ''', default_devices)
            
            conn.commit()

class Blockchain:
    def __init__(self, db_manager):
        self.db = db_manager
        self.chain = self.load_chain()
        self.difficulty = 4
        if not self.chain:
            self.create_genesis_block()
    
    def load_chain(self):
        """Load blockchain from database"""
        with self.db.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM blockchain ORDER BY block_index')
            chain = []
            for row in cursor.fetchall():
                chain.append({
                    'index': row[0],
                    'previous_hash': row[1],
                    'hash': row[2],
                    'timestamp': row[3],
                    'data': row[4]
                })
            return chain
    
    def create_genesis_block(self):
        """Create the first block in the chain"""
        genesis_data = {
            'message': 'Network Configuration Integrity Monitor Genesis Block',
            'timestamp': datetime.now().isoformat(),
            'version': '1.0'
        }
        
        genesis_block = {
            'index': 0,
            'timestamp': datetime.now().isoformat(),
            'data': json.dumps(genesis_data, sort_keys=True),
            'previous_hash': '0' * 64,
            'hash': self.calculate_block_hash(0, datetime.now().isoformat(), genesis_data, '0' * 64)
        }
        
        with self.db.get_connection() as conn:
            conn.execute('''
                INSERT INTO blockchain (block_index, previous_hash, block_hash, data)
                VALUES (?, ?, ?, ?)
            ''', (0, genesis_block['previous_hash'], genesis_block['hash'], genesis_block['data']))
            conn.commit()
        
        self.chain = [genesis_block]
        return genesis_block
    
    def calculate_block_hash(self, index, timestamp, data, previous_hash):
        """Calculate hash for a block"""
        if isinstance(data, dict):
            data_str = json.dumps(data, sort_keys=True)
        else:
            data_str = str(data)
        block_string = f"{index}{timestamp}{data_str}{previous_hash}"
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def add_block(self, data):
        """Add a new block with configuration data"""
        if not self.chain:
            self.create_genesis_block()
        
        previous_block = self.chain[-1]
        index = len(self.chain)
        
        # Mine the block with difficulty
        nonce = 0
        timestamp = datetime.now().isoformat()
        
        while True:
            block_hash = self.calculate_block_hash(index, timestamp, data, previous_block['hash'] + str(nonce))
            if block_hash[:self.difficulty] == "0" * self.difficulty:
                break
            nonce += 1
        
        block_data = {
            'index': index,
            'timestamp': timestamp,
            'data': json.dumps(data, sort_keys=True),
            'previous_hash': previous_block['hash'],
            'hash': block_hash,
            'nonce': nonce
        }
        
        with self.db.get_connection() as conn:
            conn.execute('''
                INSERT INTO blockchain (block_index, previous_hash, block_hash, data)
                VALUES (?, ?, ?, ?)
            ''', (index, block_data['previous_hash'], block_data['hash'], block_data['data']))
            conn.commit()
        
        self.chain.append(block_data)
        return block_data['hash']
    
    def is_chain_valid(self):
        """Verify the entire blockchain integrity"""
        if len(self.chain) <= 1:
            return True
        
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Verify current block's hash
            block_data = json.loads(current_block['data'])
            expected_hash = self.calculate_block_hash(
                current_block['index'],
                current_block['timestamp'],
                block_data,
                current_block['previous_hash']
            )
            
            if current_block['hash'] != expected_hash:
                return False
            
            # Verify link to previous block
            if current_block['previous_hash'] != previous_block['hash']:
                return False
        
        return True

class NetworkConfigManager:
    def __init__(self, db_manager):
        self.db = db_manager
        self.config_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.config_key)
    
    def calculate_config_hash(self, config_data):
        """Calculate SHA-256 hash of configuration data"""
        config_string = json.dumps(config_data, sort_keys=True)
        return hashlib.sha256(config_string.encode()).hexdigest()
    
    def encrypt_config(self, config_data):
        """Encrypt configuration data"""
        config_string = json.dumps(config_data)
        encrypted_data = self.cipher_suite.encrypt(config_string.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_config(self, encrypted_config):
        """Decrypt configuration data"""
        encrypted_data = base64.urlsafe_b64decode(encrypted_config.encode())
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def get_realistic_config(self, device_name, device_type):
        """Generate realistic network device configurations"""
        config_templates = {
            'router': {
                "hostname": device_name,
                "interfaces": [
                    {
                        "name": "GigabitEthernet0/0",
                        "ip_address": f"192.168.1.{random.randint(1, 254)}",
                        "subnet_mask": "255.255.255.0",
                        "status": "up"
                    },
                    {
                        "name": "GigabitEthernet0/1",
                        "ip_address": f"10.0.1.{random.randint(1, 254)}",
                        "subnet_mask": "255.255.255.0",
                        "status": "up"
                    }
                ],
                "routing": {
                    "ospf": {
                        "process_id": 1,
                        "networks": ["192.168.1.0 0.0.0.255 area 0"]
                    }
                },
                "security": {
                    "enable_secret": True,
                    "users": ["admin"]
                }
            },
            
            'switch': {
                "hostname": device_name,
                "vlans": [
                    {"id": 10, "name": "Management"},
                    {"id": 20, "name": "User_Data"},
                    {"id": 30, "name": "Voice"}
                ],
                "interfaces": {
                    "GigabitEthernet1/0/1": {"mode": "access", "vlan": 10},
                    "GigabitEthernet1/0/2": {"mode": "trunk", "vlans": [10, 20, 30]}
                }
            },
            
            'firewall': {
                "hostname": device_name,
                "interfaces": [
                    {
                        "name": "ethernet0/0",
                        "zone": "outside",
                        "ip_address": f"203.0.113.{random.randint(1, 254)}",
                        "subnet_mask": "255.255.255.0"
                    },
                    {
                        "name": "ethernet0/1", 
                        "zone": "inside",
                        "ip_address": "192.168.1.1",
                        "subnet_mask": "255.255.255.0"
                    }
                ],
                "rules": [
                    {
                        "action": "permit",
                        "source": "192.168.1.0/24",
                        "destination": "any"
                    }
                ]
            }
        }
        
        base_config = config_templates.get(device_type, config_templates['router'])
        
        # Simulate configuration changes based on tamper probability
        tamper_probability = st.session_state.get('tamper_probability', 0.2)
        if random.random() < tamper_probability:
            # Add malicious changes
            if 'security' not in base_config:
                base_config['security'] = {}
            base_config['security']['backdoor_user'] = f"attacker{random.randint(1000, 9999)}"
            base_config['unauthorized_change'] = True
        
        return base_config

class NetworkConfigMonitor:
    def __init__(self):
        self.db = DatabaseManager()
        self.blockchain = Blockchain(self.db)
        self.config_manager = NetworkConfigManager(self.db)
        self._init_session_state()
        self.load_devices()
    
    def _init_session_state(self):
        """Initialize session state variables"""
        defaults = {
            'baseline_established': False,
            'monitoring_active': False,
            'violations': [],
            'tamper_probability': 0.2,
            'auto_refresh': True,
            'baseline_hashes': {},
            'devices': []
        }
        
        for key, value in defaults.items():
            if key not in st.session_state:
                st.session_state[key] = value
    
    def load_devices(self):
        """Load devices from database"""
        with self.db.get_connection() as conn:
            cursor = conn.execute('SELECT * FROM devices')
            st.session_state.devices = []
            for row in cursor.fetchall():
                st.session_state.devices.append({
                    'id': row[0],
                    'name': row[1],
                    'ip_address': row[2],
                    'device_type': row[3],
                    'created_at': row[4]
                })
    
    def add_device(self, device_config):
        """Add a new device to monitor"""
        try:
            with self.db.get_connection() as conn:
                conn.execute('''
                    INSERT INTO devices (name, ip_address, device_type)
                    VALUES (?, ?, ?)
                ''', (
                    device_config['name'],
                    device_config['ip_address'],
                    device_config['device_type']
                ))
                conn.commit()
            self.load_devices()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def collect_configurations(self):
        """Collect configurations from all devices"""
        configs = {}
        for device in st.session_state.devices:
            config_data = self.config_manager.get_realistic_config(device['name'], device['device_type'])
            config_hash = self.config_manager.calculate_config_hash(config_data)
            
            configs[device['name']] = {
                'config': config_data,
                'hash': config_hash,
                'timestamp': datetime.now().isoformat(),
                'device_ip': device['ip_address'],
                'device_type': device['device_type']
            }
            
            # Store in database
            with self.db.get_connection() as conn:
                conn.execute('''
                    INSERT INTO configurations (device_name, config_hash, config_text)
                    VALUES (?, ?, ?)
                ''', (device['name'], config_hash, json.dumps(config_data)))
                conn.commit()
        
        return configs
    
    def establish_baseline(self):
        """Establish initial configuration baseline"""
        configs = self.collect_configurations()
        
        # Store baseline in blockchain
        blockchain_data = {}
        for device_name, data in configs.items():
            blockchain_data[device_name] = {
                'config_hash': data['hash'],
                'timestamp': data['timestamp'],
                'device_ip': data['device_ip'],
                'config_data_encrypted': self.config_manager.encrypt_config(data['config'])
            }
        
        block_hash = self.blockchain.add_block(blockchain_data)
        
        # Store baseline in session state
        st.session_state.baseline_hashes = {
            device_name: data['hash'] for device_name, data in configs.items()
        }
        st.session_state.baseline_established = True
        
        return block_hash
    
    def verify_configurations(self):
        """Verify current configurations against baseline"""
        current_configs = self.collect_configurations()
        violations = []
        
        for device_name, data in current_configs.items():
            current_hash = data['hash']
            baseline_hash = st.session_state.baseline_hashes.get(device_name)
            
            if not baseline_hash:
                st.warning(f"No baseline found for {device_name}")
                continue
            
            if current_hash != baseline_hash:
                violation = {
                    'device': device_name,
                    'timestamp': datetime.now().isoformat(),
                    'expected_hash': baseline_hash,
                    'actual_hash': current_hash,
                    'severity': 'CRITICAL',
                    'device_ip': data['device_ip'],
                    'device_type': data['device_type'],
                    'config_preview': json.dumps(data['config'], indent=2)[:500] + "..." if len(json.dumps(data['config'])) > 500 else json.dumps(data['config'], indent=2)
                }
                violations.append(violation)
                
                # Store violation in database
                with self.db.get_connection() as conn:
                    conn.execute('''
                        INSERT INTO violations (device_name, expected_hash, actual_hash, severity)
                        VALUES (?, ?, ?, ?)
                    ''', (device_name, baseline_hash, current_hash, 'CRITICAL'))
                    conn.commit()
            else:
                st.success(f"✅ {device_name}: Configuration integrity verified")
        
        st.session_state.violations = violations
        return violations

    def render_sidebar(self):
        """Render the enhanced sidebar"""
        with st.sidebar:
            st.title("🔧 Control Center")
            
            # Monitoring Controls
            st.subheader("📡 Monitoring")
            col1, col2 = st.columns(2)
            with col1:
                if st.button("▶️ Start", use_container_width=True, type="primary"):
                    st.session_state.monitoring_active = True
                    st.success("Monitoring started!")
            with col2:
                if st.button("⏹️ Stop", use_container_width=True):
                    st.session_state.monitoring_active = False
                    st.info("Monitoring stopped!")
            
            st.session_state.auto_refresh = st.checkbox("🔄 Auto-refresh", value=True)
            st.session_state.tamper_probability = st.slider("🔧 Test Tamper Probability", 0.0, 1.0, 0.2)
            
            st.divider()
            
            # Device Management
            st.subheader("🖥️ Device Management")
            with st.expander("➕ Add Device", expanded=False):
                self._render_device_form()
            
            with st.expander("📋 Device List", expanded=False):
                self._render_device_list()
            
            st.divider()
            
            # System Info
            st.subheader("ℹ️ System Info")
            st.metric("Devices", len(st.session_state.devices))
            st.metric("Blocks", len(self.blockchain.chain))
            
            active_violations = len(st.session_state.violations)
            st.metric("Active Violations", active_violations, 
                     delta=active_violations if active_violations > 0 else None,
                     delta_color="inverse" if active_violations > 0 else "off")
    
    def _render_device_form(self):
        """Render device addition form"""
        with st.form("add_device"):
            name = st.text_input("Device Name*")
            ip = st.text_input("IP Address*", placeholder="192.168.1.100")
            device_type = st.selectbox("Device Type*", ["router", "switch", "firewall", "server", "wireless"])
            
            if st.form_submit_button("Add Device", use_container_width=True):
                if all([name, ip]):
                    success = self.add_device({
                        'name': name,
                        'ip_address': ip,
                        'device_type': device_type
                    })
                    if success:
                        st.success(f"✅ Device {name} added successfully!")
                    else:
                        st.error("❌ Device name already exists!")
                else:
                    st.error("⚠️ Please fill all required fields!")
    
    def _render_device_list(self):
        """Render list of devices"""
        if not st.session_state.devices:
            st.info("No devices configured")
            return
        
        for device in st.session_state.devices:
            col1, col2 = st.columns([4, 1])
            with col1:
                st.write(f"**{device['name']}**")
                st.caption(f"📍 {device['ip_address']} | 🏷️ {device['device_type']}")
            with col2:
                if st.button("🗑️", key=f"del_{device['name']}"):
                    st.warning(f"Delete functionality for {device['name']} would be implemented here")
    
    def render_header(self):
        """Render the main header with metrics"""
        st.markdown('<h1 class="main-header">🔒 Blockchain-Powered Network Configuration Integrity Monitor</h1>', unsafe_allow_html=True)
        st.markdown("### Enterprise-grade security monitoring with immutable blockchain verification")
        
        # Key Metrics
        col1, col2, col3, col4, col5 = st.columns(5)
        
        with col1:
            st.metric("Total Devices", len(st.session_state.devices), delta=None)
        with col2:
            status = "🟢 Active" if st.session_state.monitoring_active else "🔴 Stopped"
            st.metric("Monitoring", status)
        with col3:
            st.metric("Blockchain Blocks", len(self.blockchain.chain))
        with col4:
            violations_count = len(st.session_state.violations)
            st.metric("Integrity Violations", violations_count, 
                     delta=violations_count, delta_color="inverse")
        with col5:
            chain_status = "✅ Valid" if self.blockchain.is_chain_valid() else "❌ Compromised"
            st.metric("Chain Integrity", chain_status)
    
    def render_dashboard_tab(self):
        """Render the main dashboard tab"""
        # Baseline Section
        st.markdown("### 📊 Configuration Baseline Management")
        baseline_col1, baseline_col2 = st.columns([1, 2])
        
        with baseline_col1:
            if st.button("🔄 Establish Baseline", type="primary", use_container_width=True):
                with st.spinner("Establishing secure baseline..."):
                    block_hash = self.establish_baseline()
                    st.success(f"✅ Baseline established! Block Hash: `{block_hash[:16]}...`")
                    st.rerun()
            
            if st.button("🕵️ Integrity Scan", use_container_width=True):
                with st.spinner("Scanning configurations..."):
                    violations = self.verify_configurations()
                    if violations:
                        st.error(f"🚨 Found {len(violations)} integrity violations!")
                    else:
                        st.success("✅ All configurations verified!")
                    st.rerun()
            
            # Test violation button
            if st.session_state.baseline_established:
                if st.button("🔧 Test Violation", help="Simulate a configuration violation", use_container_width=True):
                    if st.session_state.baseline_hashes:
                        device = list(st.session_state.baseline_hashes.keys())[0]
                        original_hash = st.session_state.baseline_hashes[device]
                        st.session_state.baseline_hashes[device] = "test_tampered_" + original_hash[10:]
                        st.warning(f"🔧 Test violation simulated on {device}")
                        st.rerun()
        
        with baseline_col2:
            if st.session_state.baseline_established:
                self._render_baseline_table()
            else:
                st.info("📋 No baseline established. Click 'Establish Baseline' to start monitoring.")
        
        st.divider()
        
        # Real-time Monitoring
        st.markdown("### 📡 Real-time Monitoring")
        if st.session_state.monitoring_active:
            self._render_live_monitoring()
        else:
            st.info("⏸️ Monitoring is stopped. Start monitoring to enable real-time checks.")
        
        st.divider()
        
        # Violations Display
        if st.session_state.violations:
            self._render_violations_section()
        elif st.session_state.baseline_established:
            st.success("🎉 No security violations detected! All configurations are intact.")
    
    def _render_baseline_table(self):
        """Render the baseline configuration table"""
        baseline_data = []
        for device_name, hash_value in st.session_state.baseline_hashes.items():
            is_violation = any(v['device'] == device_name for v in st.session_state.violations)
            baseline_data.append({
                'Device': device_name,
                'Baseline Hash': f"{hash_value[:16]}...",
                'Status': '❌ Violation' if is_violation else '✅ Normal',
                'Last Verified': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
        
        if baseline_data:
            df = pd.DataFrame(baseline_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
    
    def _render_live_monitoring(self):
        """Render live monitoring section"""
        status_col1, status_col2, status_col3 = st.columns(3)
        
        with status_col1:
            # Device Status
            device_status = []
            for device in st.session_state.devices:
                is_violation = any(v['device'] == device['name'] for v in st.session_state.violations)
                device_status.append({
                    'Device': device['name'],
                    'Status': '❌ Violation' if is_violation else '✅ Normal',
                    'Type': device['device_type'].title()
                })
            
            if device_status:
                status_df = pd.DataFrame(device_status)
                st.dataframe(status_df, use_container_width=True, hide_index=True)
        
        with status_col2:
            # Status Distribution
            if device_status:
                status_counts = pd.DataFrame(device_status)['Status'].value_counts()
                # FIXED: Use a simpler pie chart without complex color mapping
                fig = px.pie(values=status_counts.values, names=status_counts.index,
                           title="Device Status Distribution")
                st.plotly_chart(fig, use_container_width=True)
        
        with status_col3:
            # Monitoring Activity
            activity_data = {
                'Time': [f"T-{i}" for i in range(10, 0, -1)],
                'Config Checks': [random.randint(8, 12) for _ in range(10)],
                'Violations': [random.randint(0, 2) for _ in range(10)]
            }
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=activity_data['Time'], y=activity_data['Config Checks'],
                                   name='Config Checks', line=dict(color='blue', width=3)))
            fig.add_trace(go.Bar(x=activity_data['Time'], y=activity_data['Violations'],
                               name='Violations', marker_color='red', opacity=0.7))
            fig.update_layout(title="Monitoring Activity (Last 10 Checks)", height=300)
            st.plotly_chart(fig, use_container_width=True)
        
        # Auto-refresh for monitoring
        if st.session_state.auto_refresh and st.session_state.monitoring_active:
            time.sleep(5)
            st.rerun()
    
    def _render_violations_section(self):
        """Render the violations section"""
        st.markdown("### 🚨 Security Violations Detected")
        
        for i, violation in enumerate(st.session_state.violations):
            with st.container():
                st.markdown(f"""
                <div class="violation-alert">
                    <h3>🚨 Security Breach: {violation['device']}</h3>
                    <p><strong>Timestamp:</strong> {violation['timestamp']}</p>
                    <p><strong>Device:</strong> {violation['device']} ({violation['device_ip']})</p>
                    <p><strong>Expected Hash:</strong> <code>{violation['expected_hash'][:32]}...</code></p>
                    <p><strong>Actual Hash:</strong> <code>{violation['actual_hash'][:32]}...</code></p>
                    <p><strong>Severity:</strong> {violation['severity']}</p>
                </div>
                """, unsafe_allow_html=True)
                
                col1, col2, col3 = st.columns([2, 1, 1])
                with col1:
                    with st.expander("🔍 View Configuration Details"):
                        st.text_area("Configuration Preview", violation['config_preview'], height=200, key=f"config_{i}")
                with col2:
                    if st.button("✅ Acknowledge", key=f"ack_{i}", use_container_width=True):
                        if i < len(st.session_state.violations):
                            st.session_state.violations.pop(i)
                            st.success("Violation acknowledged!")
                            st.rerun()
                with col3:
                    if st.button("🗑️ Dismiss", key=f"dismiss_{i}", use_container_width=True):
                        if i < len(st.session_state.violations):
                            st.session_state.violations.pop(i)
                            st.info("Violation dismissed!")
                            st.rerun()
    
    def render_blockchain_tab(self):
        """Render the blockchain visualization tab"""
        st.markdown("### ⛓️ Blockchain Explorer")
        
        if not self.blockchain.chain:
            st.info("No blockchain data available. Establish a baseline first.")
            return
        
        # Blockchain Overview
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Blocks", len(self.blockchain.chain))
        with col2:
            st.metric("Chain Integrity", "✅ Valid" if self.blockchain.is_chain_valid() else "❌ Invalid")
        with col3:
            latest_block = self.blockchain.chain[-1]
            st.metric("Latest Block", f"#{latest_block['index']}")
        
        st.divider()
        
        # Blockchain Visualization
        st.markdown("#### 🔗 Block Chain Visualization")
        for block in reversed(self.blockchain.chain[-6:]):  # Show last 6 blocks
            with st.container():
                block_data = json.loads(block['data'])
                config_count = len(block_data) if isinstance(block_data, dict) else 0
                
                st.markdown(f"""
                <div class="blockchain-block">
                    <strong>Block #{block['index']}</strong> | {block['timestamp'][:19]}<br>
                    <strong>Hash:</strong> <code>{block['hash'][:24]}...</code><br>
                    <strong>Previous:</strong> <code>{block['previous_hash'][:24]}...</code><br>
                    <strong>Data:</strong> {config_count} device configurations<br>
                    <strong>Type:</strong> {block_data.get('block_type', 'genesis') if isinstance(block_data, dict) else 'genesis'}
                </div>
                """, unsafe_allow_html=True)
        
        # Blockchain Data Table
        st.divider()
        st.markdown("#### 📋 Blockchain Data")
        blockchain_data = []
        for block in self.blockchain.chain:
            block_data = json.loads(block['data'])
            config_count = len(block_data) if isinstance(block_data, dict) else 0
            blockchain_data.append({
                'Block': block['index'],
                'Hash': block['hash'][:16] + '...',
                'Previous Hash': block['previous_hash'][:16] + '...',
                'Configurations': config_count,
                'Timestamp': block['timestamp'][:19],
                'Type': block_data.get('block_type', 'genesis') if isinstance(block_data, dict) else 'genesis'
            })
        
        if blockchain_data:
            df = pd.DataFrame(blockchain_data)
            st.dataframe(df, use_container_width=True, hide_index=True)
    
    def render_analytics_tab(self):
        """Render analytics and reporting tab"""
        st.markdown("### 📈 Security Analytics & Reporting")
        
        # Generate sample analytics data
        col1, col2 = st.columns(2)
        
        with col1:
            # Violation Trends
            st.markdown("#### 🚨 Violation Trends")
            dates = pd.date_range(end=datetime.now(), periods=30, freq='D')
            violations_data = {
                'Date': dates,
                'Violations': [random.randint(0, 5) for _ in range(30)],
                'Config Changes': [random.randint(50, 100) for _ in range(30)]
            }
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(x=violations_data['Date'], y=violations_data['Violations'],
                                   name='Security Violations', line=dict(color='red', width=3)))
            fig.add_trace(go.Bar(x=violations_data['Date'], y=violations_data['Config Changes'],
                               name='Config Changes', opacity=0.3))
            fig.update_layout(title="Security Events Over Time", height=400)
            st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            # Device Compliance - FIXED: Use simpler chart to avoid recursion error
            st.markdown("#### 📊 Compliance Status")
            device_names = [d['name'] for d in st.session_state.devices]
            if device_names:
                compliance_scores = [random.randint(80, 100) for _ in device_names]
                
                # Use a simple bar chart without complex color mapping
                fig = go.Figure()
                fig.add_trace(go.Bar(
                    x=device_names,
                    y=compliance_scores,
                    marker_color='lightblue'
                ))
                fig.update_layout(
                    title="Device Compliance Scores",
                    xaxis_title="Devices",
                    yaxis_title="Compliance Score",
                    height=400
                )
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No devices to display compliance data.")
        
        # Export Reports
        st.divider()
        st.markdown("#### 📤 Report Export")
        col1, col2 = st.columns(2)
        
        with col1:
            if st.button("📄 Generate Security Report", use_container_width=True):
                report_data = {
                    'generated_at': datetime.now().isoformat(),
                    'total_devices': len(st.session_state.devices),
                    'active_violations': len(st.session_state.violations),
                    'blockchain_blocks': len(self.blockchain.chain),
                    'chain_integrity': self.blockchain.is_chain_valid(),
                    'baseline_established': st.session_state.baseline_established,
                    'monitoring_active': st.session_state.monitoring_active
                }
                
                st.download_button(
                    label="📥 Download JSON Report",
                    data=json.dumps(report_data, indent=2),
                    file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json",
                    use_container_width=True
                )
        
        with col2:
            if st.button("📊 Export Compliance Data", use_container_width=True):
                # Generate CSV data
                csv_data = pd.DataFrame({
                    'Device': [d['name'] for d in st.session_state.devices],
                    'IP Address': [d['ip_address'] for d in st.session_state.devices],
                    'Type': [d['device_type'] for d in st.session_state.devices],
                    'Status': ['Compliant' if not any(v['device'] == d['name'] for v in st.session_state.violations) else 'Non-Compliant' for d in st.session_state.devices],
                    'Last Check': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                
                st.download_button(
                    label="📥 Download CSV Report",
                    data=csv_data.to_csv(index=False),
                    file_name=f"compliance_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                    mime="text/csv",
                    use_container_width=True
                )
    
    def render_settings_tab(self):
        """Render system settings tab"""
        st.markdown("### ⚙️ System Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 🔒 Security Settings")
            scan_interval = st.number_input("Scan Interval (minutes)", min_value=1, max_value=60, value=5)
            hash_algorithm = st.selectbox("Hash Algorithm", ["SHA-256", "SHA-512", "BLAKE2"])
            enable_alerts = st.checkbox("Enable Real-time Alerts", value=True)
            store_backups = st.checkbox("Store Configuration Backups", value=True)
            
            st.markdown("#### 🗂️ Data Management")
            # FIXED: Use a safer approach to clear data
            if st.button("🔄 Clear Session Data", type="secondary", use_container_width=True):
                # Only clear specific session state variables, not everything
                keys_to_clear = ['baseline_established', 'violations', 'baseline_hashes']
                for key in keys_to_clear:
                    if key in st.session_state:
                        del st.session_state[key]
                st.session_state.monitoring_active = False
                st.success("Session data cleared! Monitoring stopped.")
                st.rerun()
            
            if st.button("💾 Backup Database", use_container_width=True):
                st.info("📦 Database backup functionality would be implemented here")
        
        with col2:
            st.markdown("#### 📧 Notification Settings")
            alert_email = st.text_input("Alert Email", placeholder="admin@company.com")
            slack_webhook = st.text_input("Slack Webhook URL", placeholder="https://hooks.slack.com/services/...")
            alert_severity = st.selectbox("Alert Severity Level", ["All", "High Only", "Critical Only"])
            
            st.markdown("#### 🔍 Advanced Options")
            debug_mode = st.checkbox("Enable Debug Mode", value=False)
            detailed_logging = st.checkbox("Detailed Logging", value=True)
            log_retention = st.number_input("Log Retention (days)", min_value=1, max_value=365, value=30)
    
    def run(self):
        """Main application runner"""
        self.render_sidebar()
        self.render_header()
        
        # Main tabs
        tab1, tab2, tab3, tab4 = st.tabs([
            "📊 Dashboard", 
            "⛓️ Blockchain", 
            "📈 Analytics", 
            "⚙️ Settings"
        ])
        
        with tab1:
            self.render_dashboard_tab()
        
        with tab2:
            self.render_blockchain_tab()
        
        with tab3:
            self.render_analytics_tab()
        
        with tab4:
            self.render_settings_tab()

def main():
    # Add a simple login (for demo purposes)
    st.sidebar.markdown("---")
    with st.sidebar:
        with st.expander("🔐 Authentication", expanded=False):
            username = st.text_input("Username", value="admin")
            password = st.text_input("Password", type="password", value="admin")
            
            if st.button("Login", use_container_width=True):
                if username == "admin" and password == "admin":
                    st.success("✅ Logged in successfully!")
                else:
                    st.error("❌ Invalid credentials")
    
    app = NetworkConfigMonitor()
    app.run()

if __name__ == "__main__":
    main()