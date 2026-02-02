"""
authentication and authorization module
handles user management, role-based access control, and permission checking
"""

import bcrypt
from datetime import datetime

class AccessManager:
    """manages user authentication and authorization"""
    
    # role definitions
    ROLES = {
        'admin': 'full access to all tables and columns',
        'analyst': 'access to aggregates and non-sensitive columns',
        'viewer': 'read-only access to public columns only'
    }
    
    def __init__(self, db_manager):
        """
        initialize access manager
        
        args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager
    
    def hash_password(self, password):
        """hash a password using bcrypt"""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return hashed.decode()
    
    def verify_password(self, password, password_hash):
        """verify a password against its hash"""
        return bcrypt.checkpw(password.encode(), password_hash.encode())
    
    def create_user(self, username, password, role):
        """
        create a new user
        
        args:
            username: unique username
            password: plaintext password (will be hashed)
            role: user role (admin, analyst, viewer)
        
        returns:
            user_id of created user
        """
        if role not in self.ROLES:
            raise ValueError(f"invalid role: {role}. must be one of {list(self.ROLES.keys())}")
        
        # hash the password
        password_hash = self.hash_password(password)
        
        # insert user
        query = """
        INSERT INTO system_users (username, password_hash, role)
        VALUES (%s, %s, %s)
        RETURNING user_id;
        """
        
        try:
            result = self.db.execute_query(query, (username, password_hash, role), fetch=True)
            user_id = result[0]['user_id']
            return user_id
        except Exception as e:
            if 'unique constraint' in str(e).lower():
                raise ValueError(f"username '{username}' already exists")
            raise
    
    def authenticate_user(self, username, password):
        """
        authenticate a user with username and password
        
        args:
            username: username
            password: plaintext password
        
        returns:
            user_id if authentication successful, None otherwise
        """
        query = """
        SELECT user_id, password_hash FROM system_users
        WHERE username = %s;
        """
        result = self.db.execute_query(query, (username,), fetch=True)
        
        if not result:
            return None
        
        user_id = result[0]['user_id']
        password_hash = result[0]['password_hash']
        
        if self.verify_password(password, password_hash):
            return user_id
        return None
    
    def get_user(self, username):
        """get user information by username"""
        query = """
        SELECT user_id, username, role, created_at
        FROM system_users
        WHERE username = %s;
        """
        result = self.db.execute_query(query, (username,), fetch=True)
        return result[0] if result else None
    
    def list_users(self):
        """list all users"""
        query = """
        SELECT user_id, username, role, created_at
        FROM system_users
        ORDER BY created_at DESC;
        """
        return self.db.execute_query(query, fetch=True)
    
    def grant_access(self, username, table_name, column_name=None, access_level='read'):
        """
        grant access to a table or specific column
        
        args:
            username: username to grant access to
            table_name: table name
            column_name: optional specific column, None means entire table
            access_level: 'read' or 'write'
        """
        user = self.get_user(username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        user_id = user['user_id']
        
        query = """
        INSERT INTO access_control (user_id, table_name, column_name, access_level)
        VALUES (%s, %s, %s, %s)
        ON CONFLICT (user_id, table_name, column_name) 
        DO UPDATE SET access_level = EXCLUDED.access_level;
        """
        
        # for postgres, we need to handle the unique constraint properly
        # first check if exists
        check_query = """
        SELECT access_id FROM access_control
        WHERE user_id = %s AND table_name = %s AND 
              (column_name = %s OR (column_name IS NULL AND %s IS NULL));
        """
        existing = self.db.execute_query(
            check_query, 
            (user_id, table_name, column_name, column_name), 
            fetch=True
        )
        
        if existing:
            # update existing
            update_query = """
            UPDATE access_control 
            SET access_level = %s, granted_at = CURRENT_TIMESTAMP
            WHERE access_id = %s;
            """
            self.db.execute_query(update_query, (access_level, existing[0]['access_id']))
        else:
            # insert new
            insert_query = """
            INSERT INTO access_control (user_id, table_name, column_name, access_level)
            VALUES (%s, %s, %s, %s);
            """
            self.db.execute_query(insert_query, (user_id, table_name, column_name, access_level))
    
    def revoke_access(self, username, table_name, column_name=None):
        """
        revoke access to a table or column
        
        args:
            username: username
            table_name: table name
            column_name: optional column name
        """
        user = self.get_user(username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        user_id = user['user_id']
        
        query = """
        DELETE FROM access_control
        WHERE user_id = %s AND table_name = %s AND 
              (column_name = %s OR (column_name IS NULL AND %s IS NULL));
        """
        self.db.execute_query(query, (user_id, table_name, column_name, column_name))
    
    def check_access(self, username, table_name, column_name=None):
        """
        check if user has access to a table or column
        
        args:
            username: username
            table_name: table name
            column_name: optional column name
        
        returns:
            True if access granted, False otherwise
        """
        user = self.get_user(username)
        if not user:
            return False
        
        # admins have access to everything
        if user['role'] == 'admin':
            return True
        
        user_id = user['user_id']
        
        # check column-specific access first
        if column_name:
            query = """
            SELECT EXISTS (
                SELECT 1 FROM access_control
                WHERE user_id = %s AND table_name = %s AND column_name = %s
            );
            """
            result = self.db.execute_query(query, (user_id, table_name, column_name), fetch=True)
            if result[0]['exists']:
                return True
        
        # check table-level access
        query = """
        SELECT EXISTS (
            SELECT 1 FROM access_control
            WHERE user_id = %s AND table_name = %s AND column_name IS NULL
        );
        """
        result = self.db.execute_query(query, (user_id, table_name), fetch=True)
        return result[0]['exists']
    
    def get_user_permissions(self, username):
        """get all permissions for a user"""
        user = self.get_user(username)
        if not user:
            raise ValueError(f"user '{username}' does not exist")
        
        user_id = user['user_id']
        
        query = """
        SELECT table_name, column_name, access_level, granted_at
        FROM access_control
        WHERE user_id = %s
        ORDER BY table_name, column_name;
        """
        return self.db.execute_query(query, (user_id,), fetch=True)
