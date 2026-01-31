"""Test the database connection and schema initialization."""

from database import DatabaseManager

def test_storage():
    print("Testing database connection...")
    
    # Initialize database manager
    db = DatabaseManager()
    
    # Initialize schema
    print("\nInitializing schema...")
    db.initialize_schema()
    
    # List tables
    print("\nListing tables...")
    tables = db.list_tables()
    print(f"Found {len(tables)} data tables")
    
    # Check system tables exist
    print("\nChecking system tables...")
    system_tables = ['system_users', 'access_control', 'compliance_log', 'master_keys']
    for table in system_tables:
        exists = db.table_exists(table)
        status = "✓" if exists else "✗"
        print(f"{status} {table}")
    
    db.close()
    print("\n✓ Storage module test complete!")

if __name__ == "__main__":
    test_storage()
