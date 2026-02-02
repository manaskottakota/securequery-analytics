"""
data pipeline module
handles csv ingestion, validation, and table creation
"""

import pandas as pd
import os

class DataLoader:
    """manages data ingestion from csv files"""
    
    def __init__(self, db_manager):
        """
        initialize data loader
        
        args:
            db_manager: DatabaseManager instance
        """
        self.db = db_manager
    
    def infer_sql_type(self, dtype):
        """
        convert pandas dtype to sql type
        
        args:
            dtype: pandas dtype
        
        returns:
            sql type string
        """
        dtype_str = str(dtype)
        
        if 'int' in dtype_str:
            return 'INTEGER'
        elif 'float' in dtype_str:
            return 'FLOAT'
        elif 'bool' in dtype_str:
            return 'BOOLEAN'
        elif 'datetime' in dtype_str:
            return 'TIMESTAMP'
        else:
            return 'TEXT'
    
    def validate_csv(self, filepath):
        """
        validate csv file exists and is readable
        
        args:
            filepath: path to csv file
        
        returns:
            dict with 'valid': bool, 'message': str, 'df': DataFrame
        """
        if not os.path.exists(filepath):
            return {
                'valid': False,
                'message': f"file not found: {filepath}",
                'df': None
            }
        
        try:
            df = pd.read_csv(filepath)
            
            if df.empty:
                return {
                    'valid': False,
                    'message': 'csv file is empty',
                    'df': None
                }
            
            return {
                'valid': True,
                'message': f'valid csv with {len(df)} rows and {len(df.columns)} columns',
                'df': df
            }
        
        except Exception as e:
            return {
                'valid': False,
                'message': f'failed to read csv: {e}',
                'df': None
            }
    
    def create_table_from_df(self, df, table_name):
        """
        create a table based on dataframe schema
        
        args:
            df: pandas DataFrame
            table_name: name for the new table
        
        returns:
            success: bool
        """
        # build column definitions
        columns = []
        for col_name, dtype in df.dtypes.items():
            sql_type = self.infer_sql_type(dtype)
            # clean column names (remove spaces, special chars)
            clean_name = col_name.lower().replace(' ', '_').replace('-', '_')
            columns.append(f"{clean_name} {sql_type}")
        
        # create table
        create_query = f"""
        CREATE TABLE IF NOT EXISTS {table_name} (
            {', '.join(columns)}
        );
        """
        
        try:
            self.db.execute_query(create_query)
            return True
        except Exception as e:
            print(f"failed to create table: {e}")
            return False
    
    def insert_data(self, df, table_name):
        """
        insert dataframe data into table
        
        args:
            df: pandas DataFrame
            table_name: target table name
        
        returns:
            number of rows inserted
        """
        # clean column names
        df.columns = [col.lower().replace(' ', '_').replace('-', '_') for col in df.columns]
        
        # get column names
        columns = list(df.columns)
        
        # build insert query
        placeholders = ', '.join(['%s'] * len(columns))
        insert_query = f"""
        INSERT INTO {table_name} ({', '.join(columns)})
        VALUES ({placeholders});
        """
        
        # insert rows
        inserted = 0
        for _, row in df.iterrows():
            try:
                values = tuple(row[col] for col in columns)
                self.db.execute_query(insert_query, values)
                inserted += 1
            except Exception as e:
                print(f"failed to insert row: {e}")
                continue
        
        return inserted
    
    def load_csv(self, filepath, table_name, drop_existing=False):
        """
        load csv file into database table
        
        args:
            filepath: path to csv file
            table_name: name for the table
            drop_existing: whether to drop existing table first
        
        returns:
            dict with 'success': bool, 'message': str, 'rows_inserted': int
        """
        # validate csv
        validation = self.validate_csv(filepath)
        if not validation['valid']:
            return {
                'success': False,
                'message': validation['message'],
                'rows_inserted': 0
            }
        
        df = validation['df']
        
        # drop existing table if requested
        if drop_existing:
            drop_query = f"DROP TABLE IF EXISTS {table_name} CASCADE;"
            try:
                self.db.execute_query(drop_query)
            except Exception as e:
                return {
                    'success': False,
                    'message': f'failed to drop existing table: {e}',
                    'rows_inserted': 0
                }
        
        # create table
        if not self.create_table_from_df(df, table_name):
            return {
                'success': False,
                'message': 'failed to create table',
                'rows_inserted': 0
            }
        
        # insert data
        rows_inserted = self.insert_data(df, table_name)
        
        if rows_inserted == 0:
            return {
                'success': False,
                'message': 'no rows were inserted',
                'rows_inserted': 0
            }
        
        return {
            'success': True,
            'message': f'successfully loaded {rows_inserted} rows into {table_name}',
            'rows_inserted': rows_inserted
        }
    
    def get_csv_preview(self, filepath, rows=5):
        """
        preview first few rows of csv
        
        args:
            filepath: path to csv file
            rows: number of rows to preview
        
        returns:
            dict with preview info
        """
        validation = self.validate_csv(filepath)
        if not validation['valid']:
            return {
                'success': False,
                'message': validation['message']
            }
        
        df = validation['df']
        preview = df.head(rows)
        
        return {
            'success': True,
            'rows': len(df),
            'columns': list(df.columns),
            'dtypes': {col: str(dtype) for col, dtype in df.dtypes.items()},
            'preview': preview.to_dict('records')
        }
