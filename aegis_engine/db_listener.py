import os
import json
import asyncio
import asyncpg
from datetime import datetime
from dotenv import load_dotenv
from gnn_model import process_event_for_ai

# Ensure secrets are loaded from .env
load_dotenv()

# Global connection reference for graceful shutdown
_conn: asyncpg.Connection = None

# In-memory storage for live alerts to power the dashboard
live_alerts = []
locked_users_list = []

async def process_notification(conn, pid, channel, payload):
    """Callback function triggered when a pg_notify is received."""
    try:
        # Securely parse the incoming JSON payload (already stringified by the DB trigger)
        event_data = json.loads(payload)
        
        # Run the event through the PyTorch GNN Model
        ai_results = process_event_for_ai(event_data)
        event_data['ai_analysis'] = ai_results
        
        # Save alert for the dashboard
        live_alerts.append(event_data)
        # Keep only the latest 50 alerts to prevent memory bloat
        if len(live_alerts) > 50:
            live_alerts.pop(0)
            
        print(f"\n[ALERT] INTRUSION DETECTION EVENT on channel '{channel}'")
        print(f"-> GNN Threat Score: {ai_results['threat_score']}% (Confidence: {ai_results['ai_confidence']}%)")
        print("-" * 50)
        # ACTIVE MITIGATION: Lockdown on Critical Threat Score
        if ai_results['threat_score'] >= 80.0:
            target_user = event_data.get('user_name')
            if target_user and target_user != 'postgres': # Never block superuser as a safety rail
                print(f"[ACTION_REQUIRED] Critical threat! Executing automated lockdown protocol on {target_user}...")
                await lockdown_user(target_user, ai_results['threat_score'])

        print(f"Time: {event_data.get('event_time')}")
        print(f"User: {event_data.get('user_name')}")
        print(f"Operation: {event_data.get('operation')} on {event_data.get('table_name')}")
        print(f"Client Source: {event_data.get('client_addr')}:{event_data.get('client_port')}")
        print(f"Application Name: {event_data.get('application_name')}")
        if event_data.get('old_record'):
            print(f"Old Record: {json.dumps(event_data.get('old_record'))}")
        if event_data.get('new_record'):
            print(f"New Record: {json.dumps(event_data.get('new_record'))}")
        print("-" * 50)
        
        # Here, we would eventually enqueue the event_data for the GNN model processing
        # enqueue_event_for_ml_analysis(event_data)

    except json.JSONDecodeError:
        print(f"[ERROR] Received malformed JSON payload on channel {channel}: {payload}")
    except Exception as e:
         print(f"[ERROR] Failed to process notification: {str(e)}")

async def get_recent_alerts():
    """Returns the most recent security alerts for the dashboard."""
    return live_alerts

async def get_locked_users():
    """Returns the list of users isolated by the automated response system."""
    return locked_users_list

async def lockdown_user(username: str, threat_score: float):
    """Automatically drops connection and locks the specified user account."""
    global _conn
    if not _conn: return
    
    # Check if already locked to prevent duplicates in our list
    if any(u['username'] == username for u in locked_users_list):
        return

    try:
        # Prevent new connections
        await _conn.execute(f'ALTER USER "{username}" NOLOGIN;')
        # Terminate active sessions
        await _conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1;", 
            username
        )
        print(f"[CRITICAL RESPONSE SUCCESS] User '{username}' has been LOCKED OUT and disconnected cleanly.")
        
        locked_users_list.append({
            "username": username,
            "timestamp": datetime.now().isoformat(),
            "reason": f"Critical AI Threat Score ({threat_score}%)"
        })
    except Exception as e:
        print(f"[ERROR] Failed to execute lockdown protocol on '{username}': {e}")

async def start_listener():
    """Starts an persistent asynchronous listener for the PostgreSQL db_event channel."""
    global _conn
    
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5432")
    db_user = os.getenv("DB_USER")
    db_password = os.getenv("DB_PASSWORD")
    db_name = os.getenv("DB_NAME")

    if not all([db_user, db_password, db_name]):
        print("[ERROR] Database credentials not fully configured in environment (.env). Listener stopping.")
        return

    try:
        _conn = await asyncpg.connect(
            user=db_user,
            password=db_password,
            database=db_name,
            host=db_host,
            port=db_port
        )
        print("[INFO] Connected to PostgreSQL Database successfully.")
        
        # Add the listener on the 'db_event' channel
        await _conn.add_listener('db_event', process_notification)
        print("[INFO] Listening on channel 'db_event' for pg_notify events...")

        # Keep the connection alive
        while True:
            await asyncio.sleep(60) 
            
    except Exception as e:
        print(f"[ERROR] Database connection/listener error: {str(e)}")
        # In a production setting, implement retry logic with exponential backoff here.

async def stop_listener():
    """Gracefully shuts down the database listener connection."""
    global _conn
    if _conn:
        try:
            await _conn.remove_listener('db_event', process_notification)
            await _conn.close()
            print("[INFO] Database listener connection closed securely.")
        except Exception as e:
             print(f"[ERROR] Error closing listener connection: {str(e)}")
