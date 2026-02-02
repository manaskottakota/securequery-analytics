"""
Database connection and schema management module.
Handles PostgreSQL connections, table creation, and basic operations.
"""

import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class DatabaseManager:
    """Manages PostgreSQL database connections and operations."""
    
    def __init__(self):
        """Initialize database connection pool."""
        self.connection_pool = None
        self._create_connection_pool()
    
    def _create_connection_pool(self):
        """Create a connection pool for efficient database access."""
        try:
            self.connection_pool = psycopg2.pool.SimpleConnectionPool(
                1, 20,  # min and max connections
                host=os.getenv('DB_HOST'),
                port=os.getenv('DB_PORT'),
                database=os.getenv('DB_NAME'),
                user=os.getenv('DB_USER'),
                password=os.getenv('DB_PASSWORD')
            )
            print("✓ Database connection pool created")
        except Exception as e:
            print(f"✗ Failed to create connection pool: {e}")
            raise
    
    def get_connection(self):
        """Get a connection from the pool."""
        return self.connection_pool.getconn()
    
    def release_connection(self, conn):
        """Release a connection back to the pool."""
        self.connection_pool.putconn(conn)
    
    def execute_query(self, query, params=None, fetch=False):
        """
        Execute a SQL query.
        
        Args:
            query: SQL query string
            params: Query parameters (tuple or dict)
            fetch: Whether to fetch results (True for SELECT, False for INSERT/UPDATE/DELETE)
        
        Returns:
            Query results if fetch=True, None otherwise
        """
        conn = self.get_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cursor:
                cursor.execute(query, params)
                
                if fetch:
                    results = cursor.fetchall()
                    conn.commit()  # commit even for selects to clear transaction
                    return results
                else:
                    conn.commit()  # commit the transaction
                    return None
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            self.release_connection(conn)
    
    def initialize_schema(self):
        """Create core system tables if they don't exist."""
        
        # System users table
        create_users_table = """
        CREATE TABLE IF NOT EXISTS system_users (
            user_id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role VARCHAR(20) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        # Access control table
        create_access_table = """
        CREATE TABLE IF NOT EXISTS access_control (
            access_id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES system_users(user_id) ON DELETE CASCADE,
            table_name VARCHAR(100) NOT NULL,
            column_name VARCHAR(100),
            access_level VARCHAR(20) DEFAULT 'read',
            granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        # Compliance log table
        create_compliance_table = """
        CREATE TABLE IF NOT EXISTS compliance_log (
            log_id SERIAL PRIMARY KEY,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER REFERENCES system_users(user_id),
            username VARCHAR(50),
            action VARCHAR(50) NOT NULL,
            query_text TEXT,
            tables_accessed TEXT,
            columns_accessed TEXT,
            status VARCHAR(20) NOT NULL,
            reason TEXT,
            ip_address VARCHAR(45)
        );
        """
        
        # Master keys table (for column encryption)
        create_keys_table = """
        CREATE TABLE IF NOT EXISTS master_keys (
            key_id SERIAL PRIMARY KEY,
            table_name VARCHAR(100) NOT NULL,
            column_name VARCHAR(100) NOT NULL,
            encrypted_key TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            rotated_at TIMESTAMP,
            UNIQUE(table_name, column_name)
        );
        """
        
        try:
            self.execute_query(create_users_table)
            self.execute_query(create_access_table)
            self.execute_query(create_compliance_table)
            self.execute_query(create_keys_table)
            print("✓ Core system tables initialized")
        except Exception as e:
            print(f"✗ Failed to initialize schema: {e}")
            raise
    
    def table_exists(self, table_name):
        """Check if a table exists in the database."""
        query = """
        SELECT EXISTS (
            SELECT FROM information_schema.tables 
            WHERE table_name = %s
        );
        """
        result = self.execute_query(query, (table_name,), fetch=True)
        return result[0]['exists']
    
    def get_table_schema(self, table_name):
        """Get the schema (columns and types) of a table."""
        query = """
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = %s
        ORDER BY ordinal_position;
        """
        return self.execute_query(query, (table_name,), fetch=True)
    
    def list_tables(self):
        """List all non-system tables in the database."""
        query = """
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' 
        AND table_name NOT IN ('system_users', 'access_control', 'compliance_log', 'master_keys')
        ORDER BY table_name;
        """
        return self.execute_query(query, fetch=True)
    
    def close(self):
        """Close all connections in the pool."""
        if self.connection_pool:
            self.connection_pool.closeall()
            print("✓ Database connections closed")
