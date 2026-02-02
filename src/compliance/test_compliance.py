"""test audit logging"""

import sys
sys.path.append('..')
from storage.database import DatabaseManager
from access.auth import AccessManager
from audit import AuditLogger

def test_compliance():
    print("testing compliance module...")
    
    # initialize
    db = DatabaseManager()
    access = AccessManager(db)
    audit = AuditLogger(db)
    
    # ensure test user exists
    print("\nensuring test user exists...")
    try:
        access.create_user('audit_test_user', 'test123', 'analyst')
    except:
        pass  # user already exists
    
    # log some actions
    print("\nlogging test actions...")
    audit.log_action('audit_test_user', 'login', 'user logged in')
    audit.log_query(
        'audit_test_user',
        'SELECT * FROM employees',
        ['employees'],
        ['name', 'email', 'salary'],
        'success'
    )
    audit.log_query(
        'audit_test_user',
        'SELECT ssn FROM employees',
        ['employees'],
        ['ssn'],
        'denied',
        'no access to column employees.ssn'
    )
    print("✓ test actions logged")
    
    # get user logs
    print("\ngetting logs for audit_test_user...")
    logs = audit.get_user_logs('audit_test_user', limit=10)
    print(f"found {len(logs)} log entries")
    print(audit.format_logs(logs))
    
    # get denied access logs
    print("\ngetting denied access attempts...")
    denied = audit.get_denied_access_logs(limit=5)
    print(f"found {len(denied)} denied access attempts")
    print(audit.format_logs(denied))
    
    # get recent logs
    print("\ngetting recent logs...")
    recent = audit.get_recent_logs(limit=5)
    print(audit.format_logs(recent))
    
    # export logs
    print("\nexporting logs to file...")
    count = audit.export_logs('audit_logs.csv')
    print(f"✓ exported {count} log entries to audit_logs.csv")
    
    db.close()
    print("\n✓ compliance module test complete")

if __name__ == "__main__":
    test_compliance()
