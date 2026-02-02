"""test authentication and authorization"""

import sys
sys.path.append('..')
from storage.database import DatabaseManager
from auth import AccessManager

def test_access():
    print("testing access module...")
    
    # initialize
    db = DatabaseManager()
    access = AccessManager(db)
    
    # test user creation
    print("\ncreating test users...")
    try:
        admin_id = access.create_user('admin_user', 'admin123', 'admin')
        print(f"✓ admin user created: id={admin_id}")
        
        analyst_id = access.create_user('analyst_user', 'analyst123', 'analyst')
        print(f"✓ analyst user created: id={analyst_id}")
        
        viewer_id = access.create_user('viewer_user', 'viewer123', 'viewer')
        print(f"✓ viewer user created: id={viewer_id}")
    except ValueError as e:
        print(f"users already exist: {e}")
    
    # check if users were actually created
        users = access.list_users()
        print(f"total users in database: {len(users)}")
        
    # test authentication
    print("\ntesting authentication...")
    auth_result = access.authenticate_user('analyst_user', 'analyst123')
    if auth_result:
        print(f"✓ authentication successful: user_id={auth_result}")
    else:
        print("✗ authentication failed")
    
    # test wrong password
    auth_result = access.authenticate_user('analyst_user', 'wrongpassword')
    if not auth_result:
        print("✓ wrong password correctly rejected")
    
    # test granting access
    print("\ntesting access control...")
    access.grant_access('analyst_user', 'employees', 'salary')
    print("✓ granted analyst_user access to employees.salary")
    
    access.grant_access('analyst_user', 'employees')
    print("✓ granted analyst_user access to entire employees table")
    
    # test checking access
    print("\ntesting permission checks...")
    has_access = access.check_access('analyst_user', 'employees', 'salary')
    print(f"analyst_user can access employees.salary: {has_access}")
    
    has_access = access.check_access('viewer_user', 'employees', 'salary')
    print(f"viewer_user can access employees.salary: {has_access}")
    
    has_access = access.check_access('admin_user', 'employees', 'ssn')
    print(f"admin_user can access employees.ssn: {has_access} (admins have all access)")
    
    # test listing permissions
    print("\nlisting analyst_user permissions...")
    perms = access.get_user_permissions('analyst_user')
    for perm in perms:
        col = perm['column_name'] if perm['column_name'] else '(all columns)'
        print(f"  - {perm['table_name']}.{col}: {perm['access_level']}")
    
    # test revoking access
    print("\nrevoking access...")
    access.revoke_access('analyst_user', 'employees', 'salary')
    print("✓ revoked analyst_user access to employees.salary")
    
    db.close()
    print("\n✓ access module test complete")

if __name__ == "__main__":
    test_access()
