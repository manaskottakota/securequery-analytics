"""test query engine"""

import sys
sys.path.append('..')
from storage.database import DatabaseManager
from access.auth import AccessManager
from security.encryption import EncryptionManager
from query_engine import QueryEngine

def test_engine():
    print("testing query engine...")
    
    # initialize
    db = DatabaseManager()
    access = AccessManager(db)
    crypto = EncryptionManager(db)
    engine = QueryEngine(db, access, crypto)
    
    # create a test table with sample data
    print("\ncreating test table...")
    db.execute_query("DROP TABLE IF EXISTS employees CASCADE;")
    create_table = """
    CREATE TABLE IF NOT EXISTS employees (
        employee_id SERIAL PRIMARY KEY,
        name VARCHAR(100),
        email VARCHAR(100),
        ssn TEXT,
        salary INTEGER,
        department VARCHAR(50)
    );
    """
    db.execute_query(create_table)
    
    # insert sample data
    insert_data = """
    INSERT INTO employees (name, email, ssn, salary, department) VALUES
    ('john smith', 'john@company.com', '123-45-6789', 85000, 'engineering'),
    ('jane doe', 'jane@company.com', '987-65-4321', 92000, 'engineering'),
    ('bob johnson', 'bob@company.com', '555-12-3456', 78000, 'sales')
    ON CONFLICT DO NOTHING;
    """
    db.execute_query(insert_data)
    print("✓ test table created with sample data")
    
    # encrypt ssn column
    print("\nencrypting ssn column...")
    crypto.generate_column_key('employees', 'ssn')
    
    # get all ssns and encrypt them
    rows = db.execute_query("SELECT employee_id, ssn FROM employees", fetch=True)
    for row in rows:
        encrypted_ssn = crypto.encrypt_value(row['ssn'], 'employees', 'ssn')
        db.execute_query(
            "UPDATE employees SET ssn = %s WHERE employee_id = %s",
            (encrypted_ssn, row['employee_id'])
        )
    print("✓ ssn column encrypted")
    
    # create test users if they don't exist
    print("\nensuring test users exist...")
    try:
        access.create_user('test_admin', 'admin123', 'admin')
        access.create_user('test_analyst', 'analyst123', 'analyst')
    except:
        pass  # users already exist
    
    # grant permissions
    access.grant_access('test_analyst', 'employees')
    access.grant_access('test_analyst', 'employees', 'salary')
    print("✓ permissions granted")
    
    # test query parsing
    print("\ntesting query parsing...")
    parsed = engine.parse_query("SELECT name, salary FROM employees WHERE department = 'engineering'")
    print(f"parsed query: {parsed}")
    
    # test query execution as admin (can see ssn)
    print("\ntesting query as admin...")
    result = engine.execute_query('test_admin', "SELECT name, email, ssn FROM employees LIMIT 2")
    print(engine.format_results(result))
    
    # test query execution as analyst (cannot see ssn)
    print("\ntesting query as analyst (ssn should be masked)...")
    result = engine.execute_query('test_analyst', "SELECT name, salary FROM employees WHERE department = 'engineering'")
    print(engine.format_results(result))
    
    # test unauthorized access
    print("\ntesting unauthorized access...")
    result = engine.execute_query('test_analyst', "SELECT name, ssn FROM employees")
    print(f"result: {result['message']}")
    if 'denied_items' in result:
        for item in result['denied_items']:
            print(f"  - {item}")
    
    db.close()
    print("\n✓ query engine test complete")

if __name__ == "__main__":
    test_engine()
