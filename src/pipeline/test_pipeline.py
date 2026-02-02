"""test data pipeline"""

import sys
sys.path.append('..')
from storage.database import DatabaseManager
from data_loader import DataLoader

def test_pipeline():
    print("testing data pipeline...")
    
    # initialize
    db = DatabaseManager()
    loader = DataLoader(db)
    
    # preview csv
    print("\npreviewing sample csv...")
    preview = loader.get_csv_preview('sample_data.csv')
    if preview['success']:
        print(f"✓ found {preview['rows']} rows with columns: {preview['columns']}")
        print(f"data types: {preview['dtypes']}")
        print("\nfirst 3 rows:")
        for i, row in enumerate(preview['preview'][:3], 1):
            print(f"  {i}. {row['name']} - {row['department']} - ${row['salary']}")
    
    # load csv into database
    print("\nloading csv into database...")
    result = loader.load_csv('sample_data.csv', 'test_employees', drop_existing=True)
    
    if result['success']:
        print(f"✓ {result['message']}")
    else:
        print(f"✗ {result['message']}")
    
    # verify data was loaded
    print("\nverifying loaded data...")
    query_result = db.execute_query("SELECT * FROM test_employees", fetch=True)
    print(f"✓ found {len(query_result)} rows in test_employees table")
    
    # show first few rows
    print("\nfirst 3 rows from database:")
    for i, row in enumerate(query_result[:3], 1):
        print(f"  {i}. {row['name']} - {row['department']} - ${row['salary']}")
    
    db.close()
    print("\n✓ pipeline module test complete")

if __name__ == "__main__":
    test_pipeline()
