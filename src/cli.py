"""
command-line interface for securequery analytics
ties together all modules for complete functionality
"""

import click
import sys
from storage.database import DatabaseManager
from access.auth import AccessManager
from security.encryption import EncryptionManager
from engine.query_engine import QueryEngine
from compliance.audit import AuditLogger
from pipeline.data_loader import DataLoader

# global instances
db = None
access = None
crypto = None
engine = None
audit = None
loader = None

def init_modules():
    """initialize all modules"""
    global db, access, crypto, engine, audit, loader
    
    try:
        db = DatabaseManager()
        access = AccessManager(db)
        crypto = EncryptionManager(db)
        engine = QueryEngine(db, access, crypto)
        audit = AuditLogger(db)
        loader = DataLoader(db)
    except Exception as e:
        click.echo(f"✗ failed to initialize: {e}")
        sys.exit(1)

@click.group()
def cli():
    """securequery analytics - secure data warehouse with role-based access control"""
    init_modules()

# setup commands

@cli.command()
def initialize():
    """initialize database schema and core tables"""
    try:
        db.initialize_schema()
        click.echo("✓ database initialized successfully")
    except Exception as e:
        click.echo(f"✗ initialization failed: {e}")

@cli.command()
def reset_database():
    """drop all tables and reinitialize (use with caution)"""
    if click.confirm("this will delete all data. are you sure?"):
        try:
            # drop all tables
            tables = ['compliance_log', 'access_control', 'master_keys', 'system_users']
            for table in tables:
                db.execute_query(f"DROP TABLE IF EXISTS {table} CASCADE")
            
            # reinitialize
            db.initialize_schema()
            click.echo("✓ database reset successfully")
        except Exception as e:
            click.echo(f"✗ reset failed: {e}")

# data management commands

@cli.command()
@click.argument('csv_file')
@click.argument('table_name')
@click.option('--drop', is_flag=True, help='drop existing table first')
def load(csv_file, table_name, drop):
    """load csv data into a table"""
    try:
        result = loader.load_csv(csv_file, table_name, drop_existing=drop)
        if result['success']:
            click.echo(f"✓ {result['message']}")
        else:
            click.echo(f"✗ {result['message']}")
    except Exception as e:
        click.echo(f"✗ load failed: {e}")

@cli.command()
@click.argument('table_name')
@click.argument('column_name')
def secure_column(table_name, column_name):
    """mark a column for encryption"""
    try:
        # generate encryption key
        crypto.generate_column_key(table_name, column_name)
        
        # encrypt existing data
        rows = db.execute_query(f"SELECT * FROM {table_name}", fetch=True)
        for row in rows:
            if column_name in row and row[column_name]:
                encrypted = crypto.encrypt_value(row[column_name], table_name, column_name)
                # find primary key column (assume first column is primary key)
                pk_col = list(row.keys())[0]
                pk_val = row[pk_col]
                db.execute_query(
                    f"UPDATE {table_name} SET {column_name} = %s WHERE {pk_col} = %s",
                    (encrypted, pk_val)
                )
        
        click.echo(f"✓ encrypted column {table_name}.{column_name} ({len(rows)} rows)")
    except Exception as e:
        click.echo(f"✗ encryption failed: {e}")

@cli.command()
def list_tables():
    """list all data tables"""
    try:
        tables = db.list_tables()
        if tables:
            click.echo("data tables:")
            for table in tables:
                click.echo(f"  - {table['table_name']}")
        else:
            click.echo("no data tables found")
    except Exception as e:
        click.echo(f"✗ failed to list tables: {e}")

@cli.command()
@click.argument('table_name')
def describe(table_name):
    """show table schema"""
    try:
        schema = db.get_table_schema(table_name)
        if schema:
            click.echo(f"schema for {table_name}:")
            for col in schema:
                encrypted = "🔒" if crypto.is_column_encrypted(table_name, col['column_name']) else ""
                click.echo(f"  - {col['column_name']}: {col['data_type']} {encrypted}")
        else:
            click.echo(f"table '{table_name}' not found")
    except Exception as e:
        click.echo(f"✗ failed to describe table: {e}")

# user management commands

@cli.command()
@click.argument('username')
@click.argument('password')
@click.argument('role', type=click.Choice(['admin', 'analyst', 'viewer']))
def add_user(username, password, role):
    """create a new user"""
    try:
        user_id = access.create_user(username, password, role)
        click.echo(f"✓ user '{username}' created with role '{role}' (id: {user_id})")
        audit.log_action('system', 'create_user', f"created user {username} with role {role}")
    except Exception as e:
        click.echo(f"✗ failed to create user: {e}")

@cli.command()
def list_users():
    """list all users"""
    try:
        users = access.list_users()
        if users:
            click.echo("users:")
            for user in users:
                click.echo(f"  - {user['username']} ({user['role']}) - created {user['created_at']}")
        else:
            click.echo("no users found")
    except Exception as e:
        click.echo(f"✗ failed to list users: {e}")

# access control commands

@cli.command()
@click.argument('username')
@click.argument('table_name')
@click.argument('column_name', required=False)
def allow(username, table_name, column_name):
    """grant access to table or column"""
    try:
        access.grant_access(username, table_name, column_name)
        target = f"{table_name}.{column_name}" if column_name else table_name
        click.echo(f"✓ granted {username} access to {target}")
        audit.log_action('system', 'grant_access', f"granted {username} access to {target}")
    except Exception as e:
        click.echo(f"✗ failed to grant access: {e}")

@cli.command()
@click.argument('username')
@click.argument('table_name')
@click.argument('column_name', required=False)
def deny(username, table_name, column_name):
    """revoke access to table or column"""
    try:
        access.revoke_access(username, table_name, column_name)
        target = f"{table_name}.{column_name}" if column_name else table_name
        click.echo(f"✓ revoked {username} access to {target}")
        audit.log_action('system', 'revoke_access', f"revoked {username} access to {target}")
    except Exception as e:
        click.echo(f"✗ failed to revoke access: {e}")

@cli.command()
@click.argument('username')
def permissions(username):
    """show user permissions"""
    try:
        perms = access.get_user_permissions(username)
        if perms:
            click.echo(f"permissions for {username}:")
            for perm in perms:
                col = perm['column_name'] if perm['column_name'] else '(all columns)'
                click.echo(f"  - {perm['table_name']}.{col}: {perm['access_level']}")
        else:
            click.echo(f"no permissions found for {username}")
    except Exception as e:
        click.echo(f"✗ failed to get permissions: {e}")

# query commands

@cli.command()
@click.argument('username')
@click.argument('sql')
def execute(username, sql):
    """execute sql query as a user"""
    try:
        result = engine.execute_query(username, sql)
        
        # log the query
        parsed = engine.parse_query(sql)
        status = 'success' if result['success'] else 'denied'
        reason = result.get('message') if not result['success'] else None
        audit.log_query(username, sql, parsed['tables'], parsed['columns'], status, reason)
        
        # display results
        click.echo(engine.format_results(result))
    except Exception as e:
        click.echo(f"✗ query failed: {e}")

@cli.command()
@click.argument('username')
@click.argument('sql')
def validate(username, sql):
    """validate query permissions without executing"""
    try:
        parsed = engine.parse_query(sql)
        validation = engine.validate_permissions(username, parsed['tables'], parsed['columns'])
        
        if validation['allowed']:
            click.echo(f"✓ query allowed for {username}")
            click.echo(f"  tables: {', '.join(parsed['tables'])}")
            click.echo(f"  columns: {', '.join(parsed['columns'])}")
        else:
            click.echo(f"✗ query denied for {username}")
            click.echo(f"  reason: {validation['reason']}")
            for item in validation['denied_items']:
                click.echo(f"  - {item}")
    except Exception as e:
        click.echo(f"✗ validation failed: {e}")

# audit commands

@cli.command()
@click.argument('username')
@click.option('--limit', default=20, help='number of logs to show')
def logs(username, limit):
    """show audit logs for a user"""
    try:
        logs_data = audit.get_user_logs(username, limit)
        if logs_data:
            click.echo(f"audit logs for {username}:")
            click.echo(audit.format_logs(logs_data))
        else:
            click.echo(f"no logs found for {username}")
    except Exception as e:
        click.echo(f"✗ failed to get logs: {e}")

@cli.command()
@click.argument('table_name')
@click.option('--limit', default=20, help='number of logs to show')
def logs_table(table_name, limit):
    """show audit logs for a table"""
    try:
        logs_data = audit.get_table_logs(table_name, limit)
        if logs_data:
            click.echo(f"audit logs for {table_name}:")
            click.echo(audit.format_logs(logs_data))
        else:
            click.echo(f"no logs found for {table_name}")
    except Exception as e:
        click.echo(f"✗ failed to get logs: {e}")

@cli.command()
@click.option('--limit', default=20, help='number of logs to show')
def logs_recent(limit):
    """show recent audit logs"""
    try:
        logs_data = audit.get_recent_logs(limit)
        if logs_data:
            click.echo("recent audit logs:")
            click.echo(audit.format_logs(logs_data))
        else:
            click.echo("no logs found")
    except Exception as e:
        click.echo(f"✗ failed to get logs: {e}")

if __name__ == '__main__':
    cli()
