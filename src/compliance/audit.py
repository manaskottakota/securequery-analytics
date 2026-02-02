"""
audit logging module
tracks all database operations for compliance and security monitoring
"""

from datetime import datetime

class AuditLogger:
    """manages compliance audit logs"""
    
    def __init__(self, db_manager):
        """
        initialize audit logger
        
        args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager
    
    def log_query(self, username, query, tables, columns, status, reason=None):
        """
        log a query execution attempt
        
        args:
            username: user who executed query
            query: sql query text
            tables: list of tables accessed
            columns: list of columns accessed
            status: 'success' or 'denied'
            reason: optional reason for denial
        """
        # get user_id
        user_query = "SELECT user_id FROM system_users WHERE username = %s"
        user_result = self.db.execute_query(user_query, (username,), fetch=True)
        user_id = user_result[0]['user_id'] if user_result else None
        
        # convert lists to strings
        tables_str = ', '.join(tables) if tables else None
        columns_str = ', '.join(columns) if columns else None
        
        # insert log entry
        insert_query = """
        INSERT INTO compliance_log 
        (user_id, username, action, query_text, tables_accessed, columns_accessed, status, reason)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
        """
        
        self.db.execute_query(
            insert_query,
            (user_id, username, 'query', query, tables_str, columns_str, status, reason)
        )
    
    def log_action(self, username, action, details=None, status='success'):
        """
        log a non-query action (user creation, permission grant, etc)
        
        args:
            username: user who performed action
            action: action type (create_user, grant_access, etc)
            details: optional details about the action
            status: success or failure
        """
        user_query = "SELECT user_id FROM system_users WHERE username = %s"
        user_result = self.db.execute_query(user_query, (username,), fetch=True)
        user_id = user_result[0]['user_id'] if user_result else None
        
        insert_query = """
        INSERT INTO compliance_log 
        (user_id, username, action, query_text, status, reason)
        VALUES (%s, %s, %s, %s, %s, %s);
        """
        
        self.db.execute_query(
            insert_query,
            (user_id, username, action, details, status, None)
        )
    
    def get_user_logs(self, username, limit=20):
        """
        get audit logs for a specific user
        
        args:
            username: username to get logs for
            limit: max number of logs to return
        
        returns:
            list of log entries
        """
        query = """
        SELECT timestamp, action, query_text, tables_accessed, columns_accessed, status, reason
        FROM compliance_log
        WHERE username = %s
        ORDER BY timestamp DESC
        LIMIT %s;
        """
        return self.db.execute_query(query, (username, limit), fetch=True)
    
    def get_table_logs(self, table_name, limit=20):
        """
        get audit logs for a specific table
        
        args:
            table_name: table to get logs for
            limit: max number of logs to return
        
        returns:
            list of log entries
        """
        query = """
        SELECT timestamp, username, action, query_text, columns_accessed, status, reason
        FROM compliance_log
        WHERE tables_accessed LIKE %s
        ORDER BY timestamp DESC
        LIMIT %s;
        """
        return self.db.execute_query(query, (f'%{table_name}%', limit), fetch=True)
    
    def get_recent_logs(self, limit=20):
        """
        get most recent audit logs
        
        args:
            limit: max number of logs to return
        
        returns:
            list of log entries
        """
        query = """
        SELECT timestamp, username, action, query_text, tables_accessed, status, reason
        FROM compliance_log
        ORDER BY timestamp DESC
        LIMIT %s;
        """
        return self.db.execute_query(query, (limit,), fetch=True)
    
    def get_denied_access_logs(self, limit=20):
        """
        get logs of denied access attempts
        
        args:
            limit: max number of logs to return
        
        returns:
            list of denied access log entries
        """
        query = """
        SELECT timestamp, username, action, query_text, tables_accessed, columns_accessed, status, reason
        FROM compliance_log
        WHERE status = 'denied'
        ORDER BY timestamp DESC
        LIMIT %s;
        """
        return self.db.execute_query(query, (limit,), fetch=True)
    
    def format_logs(self, logs):
        """
        format logs as readable text
        
        args:
            logs: list of log entries
        
        returns:
            formatted string
        """
        if not logs:
            return "no logs found"
        
        output = []
        for log in logs:
            timestamp = log['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            username = log.get('username', 'system')
            action = log['action']
            status = log['status']
            
            line = f"[{timestamp}] {username} | {action} | {status}"
            
            if log.get('tables_accessed'):
                line += f" | tables: {log['tables_accessed']}"
            
            if log.get('columns_accessed'):
                line += f" | columns: {log['columns_accessed']}"
            
            if log.get('reason'):
                line += f" | reason: {log['reason']}"
            
            output.append(line)
        
        return '\n'.join(output)
    
    def export_logs(self, filename, start_date=None, end_date=None):
        """
        export logs to a file
        
        args:
            filename: output file path
            start_date: optional start date filter
            end_date: optional end date filter
        """
        query = "SELECT * FROM compliance_log WHERE 1=1"
        params = []
        
        if start_date:
            query += " AND timestamp >= %s"
            params.append(start_date)
        
        if end_date:
            query += " AND timestamp <= %s"
            params.append(end_date)
        
        query += " ORDER BY timestamp DESC"
        
        logs = self.db.execute_query(query, tuple(params) if params else None, fetch=True)
        
        with open(filename, 'w') as f:
            f.write("timestamp,user_id,username,action,query_text,tables_accessed,columns_accessed,status,reason\n")
            for log in logs:
                f.write(f"{log['timestamp']},{log['user_id']},{log['username']},{log['action']},")
                f.write(f'"{log.get("query_text", "")}",{log.get("tables_accessed", "")},')
                f.write(f'{log.get("columns_accessed", "")},{log["status"]},{log.get("reason", "")}\n')
        
        return len(logs)
