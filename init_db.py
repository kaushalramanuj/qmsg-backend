import asyncio
import sys
import os

# Add the current directory to Python path so we can import from app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.database import init_db

async def main():
    print("Creating database tables...")
    try:
        await init_db()
        print("Database tables created successfully!")
    except Exception as e:
        print(f"Error creating database tables: {e}")

if __name__ == "__main__":
    asyncio.run(main())