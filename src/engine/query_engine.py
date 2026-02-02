"""
query engine module
parses sql queries, validates permissions, and executes with access control
"""

import sqlparse
from sqlparse.sql import IdentifierList, Identifier, Where, Token
from sqlparse.tokens import Keyword, DML

class QueryEngine:
    """handles sql query parsing, validation, and execution"""
    
    def __init__(self, db_manager, access_manager, encryption_manager):
        """
        initialize query engine
        
        args:
            db_manager: DatabaseManager instance
            access_manager: AccessManager instance
            encryption_manager: EncryptionManager instance
        """
        self.db = db_manager
        self.access = access_manager
        self.crypto = encryption_manager
    
    def parse_query(self, sql):
        """
        parse sql query to extract tables and columns
        
        args:
            sql: sql query string
        
        returns:
            dict with 'tables' and 'columns' lists
        """
        parsed = sqlparse.parse(sql)[0]
        
        tables = []
        columns = []
        
        # extract statement type
        stmt_type = None
        for token in parsed.tokens:
            if token.ttype is DML:
                stmt_type = token.value.upper()
                break
        
        # extract tables from FROM clause
        from_seen = False
        for token in parsed.tokens:
            if from_seen:
                if isinstance(token, IdentifierList):
                    for identifier in token.get_identifiers():
                        tables.append(identifier.get_real_name())
                elif isinstance(token, Identifier):
                    tables.append(token.get_real_name())
                elif token.ttype is Keyword:
                    break
            if token.ttype is Keyword and token.value.upper() == 'FROM':
                from_seen = True
        
        # extract columns from SELECT clause
        if stmt_type == 'SELECT':
            select_seen = False
            for token in parsed.tokens:
                if token.ttype is DML and token.value.upper() == 'SELECT':
                    select_seen = True
                    continue
                
                if select_seen:
                    if token.ttype is Keyword and token.value.upper() == 'FROM':
                        break
                    
                    if isinstance(token, IdentifierList):
                        for identifier in token.get_identifiers():
                            col_name = identifier.get_real_name()
                            if col_name != '*':
                                columns.append(col_name)
                    elif isinstance(token, Identifier):
                        col_name = token.get_real_name()
                        if col_name != '*':
                            columns.append(col_name)
                    elif token.ttype is None and str(token).strip() == '*':
                        columns.append('*')
        
        return {
            'type': stmt_type,
            'tables': tables,
            'columns': columns
        }
    
    def validate_permissions(self, username, tables, columns):
        """
        check if user has permission to access tables and columns
        
        args:
            username: username
            tables: list of table names
            columns: list of column names (or ['*'] for all)
        
        returns:
            dict with 'allowed': bool, 'reason': str, 'denied_items': list
        """
        user = self.access.get_user(username)
        if not user:
            return {
                'allowed': False,
                'reason': f"user '{username}' does not exist",
                'denied_items': []
            }
        
        # admins can access everything
        if user['role'] == 'admin':
            return {
                'allowed': True,
                'reason': 'admin has full access',
                'denied_items': []
            }
        
        denied_items = []
        
        # check table access
        for table in tables:
            if not self.db.table_exists(table):
                denied_items.append(f"table '{table}' does not exist")
                continue
            
            if not self.access.check_access(username, table):
                denied_items.append(f"no access to table '{table}'")
        
        # check column access if specific columns requested
        if columns and '*' not in columns:
            for table in tables:
                for column in columns:
                    if not self.access.check_access(username, table, column):
                        denied_items.append(f"no access to column '{table}.{column}'")
        
        if denied_items:
            return {
                'allowed': False,
                'reason': 'insufficient permissions',
                'denied_items': denied_items
            }
        
        return {
            'allowed': True,
            'reason': 'access granted',
            'denied_items': []
        }
    
    def get_table_columns(self, table_name):
        """get all column names for a table"""
        schema = self.db.get_table_schema(table_name)
        return [col['column_name'] for col in schema]
    
    def execute_query(self, username, sql):
        """
        execute a sql query with access control
        
        args:
            username: username executing the query
            sql: sql query string
        
        returns:
            dict with 'success': bool, 'data': list, 'message': str, 'columns': list
        """
        # parse the query
        try:
            parsed = self.parse_query(sql)
        except Exception as e:
            return {
                'success': False,
                'data': [],
                'message': f"failed to parse query: {e}",
                'columns': []
            }
        
        tables = parsed['tables']
        columns = parsed['columns']
        
        # if SELECT *, expand to actual columns
        if '*' in columns:
            columns = []
            for table in tables:
                columns.extend(self.get_table_columns(table))
        
        # validate permissions
        validation = self.validate_permissions(username, tables, columns)
        
        if not validation['allowed']:
            return {
                'success': False,
                'data': [],
                'message': validation['reason'],
                'denied_items': validation['denied_items'],
                'columns': []
            }
        
        # execute the query
        try:
            results = self.db.execute_query(sql, fetch=True)
            
            if not results:
                return {
                    'success': True,
                    'data': [],
                    'message': 'query executed successfully, no results',
                    'columns': []
                }
            
            # decrypt encrypted columns if user has access
            decrypted_results = []
            column_names = list(results[0].keys())
            
            for row in results:
                decrypted_row = {}
                for col_name in column_names:
                    value = row[col_name]
                    
                    # check if column is encrypted
                    is_encrypted = False
                    for table in tables:
                        if self.crypto.is_column_encrypted(table, col_name):
                            is_encrypted = True
                            
                            # check if user has access to this encrypted column
                            if self.access.check_access(username, table, col_name):
                                # decrypt for authorized user
                                try:
                                    value = self.crypto.decrypt_value(value, table, col_name)
                                except:
                                    value = '[decryption error]'
                            else:
                                # mask for unauthorized user
                                value = self.crypto.mask_value(value, 'partial')
                            break
                    
                    decrypted_row[col_name] = value
                
                decrypted_results.append(decrypted_row)
            
            return {
                'success': True,
                'data': decrypted_results,
                'message': f'query executed successfully, {len(decrypted_results)} rows returned',
                'columns': column_names
            }
        
        except Exception as e:
            return {
                'success': False,
                'data': [],
                'message': f"query execution failed: {e}",
                'columns': []
            }
    
    def format_results(self, results):
        """
        format query results as a table string
        
        args:
            results: dict from execute_query
        
        returns:
            formatted string
        """
        if not results['success']:
            return f"✗ {results['message']}"
        
        if not results['data']:
            return f"✓ {results['message']}"
        
        # get column names and data
        columns = results['columns']
        data = results['data']
        
        # calculate column widths
        col_widths = {}
        for col in columns:
            col_widths[col] = len(col)
            for row in data:
                val_len = len(str(row[col]))
                if val_len > col_widths[col]:
                    col_widths[col] = val_len
        
        # build header
        header = ' | '.join([col.ljust(col_widths[col]) for col in columns])
        separator = '-+-'.join(['-' * col_widths[col] for col in columns])
        
        # build rows
        rows = []
        for row in data:
            row_str = ' | '.join([str(row[col]).ljust(col_widths[col]) for col in columns])
            rows.append(row_str)
        
        # combine
        output = f"\n{header}\n{separator}\n"
        output += '\n'.join(rows)
        output += f"\n\n✓ {results['message']}"
        
        return output
