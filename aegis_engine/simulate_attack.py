import asyncio
import asyncpg
from dotenv import load_dotenv
import os

# Load environment variables (ensure .env exists with correct credentials)
load_dotenv()

async def simulate_attack():
    print("==================================================")
    print("Initiating simulated attack on Honeytoken table...")
    print("==================================================")
    try:
        conn = await asyncpg.connect(
            user=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "your_secure_password_here"),
            database=os.getenv("DB_NAME", "aegis_db"),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432")
        )
        
        # 1. Simulate an unauthorized UPDATE
        print("[ATTACK 1] Executing unauthorized UPDATE on audit.honeytoken_registry...")
        await conn.execute("""
            UPDATE audit.honeytoken_registry 
            SET sensitive_data_1 = 'COMPROMISED_EXTRACTED_KEY' 
            WHERE id = 1;
        """)
        print("[SUCCESS] UPDATE executed.")
        
        await asyncio.sleep(2) # Brief pause to separate events

        # 2. Simulate an unauthorized DELETE
        print("\n[ATTACK 2] Executing unauthorized DELETE on audit.honeytoken_registry...")
        await conn.execute("""
            DELETE FROM audit.honeytoken_registry 
            WHERE id = 2;
        """)
        print("[SUCCESS] DELETE executed.")

        await conn.close()
        print("\n==================================================")
        print("Simulated attack complete. Check the Intelligence Engine logs!")
        print("==================================================")
    except Exception as e:
        print(f"\n[ERROR] Error during attack simulation: {e}")
        print("Make sure your PostgreSQL database is running and .env is configured correctly.")

if __name__ == "__main__":
    asyncio.run(simulate_attack())
