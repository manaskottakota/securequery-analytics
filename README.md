# SecureQuery Analytics Platform

secure data warehouse with role-based access control, column-level encryption, and audit logging for compliance

## what it does

- load csv data into postgresql database
- encrypt sensitive columns (ssn, credit cards, salaries)
- create users with different permission levels (admin/analyst/viewer)
- control who can see which tables and columns
- execute sql queries with automatic permission checks
- decrypt data only for authorized users
- log every query and access attempt for audits

## setup
```bash
# install postgresql
brew install postgresql@14
brew services start postgresql@14

# create database
psql postgres -c "CREATE DATABASE securequery;"
psql postgres -c "CREATE USER sqadmin WITH PASSWORD 'SecurePass123';"
psql postgres -c "GRANT ALL PRIVILEGES ON DATABASE securequery TO sqadmin;"

# install python dependencies
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

# create .env file
cat > .env << EOF
DB_HOST=localhost
DB_PORT=5432
DB_NAME=securequery
DB_USER=sqadmin
DB_PASSWORD=SecurePass123
MASTER_KEY_PASSPHRASE=your_secure_passphrase
LOG_LEVEL=INFO
EOF

# initialize database
python3 src/cli.py initialize
```

## how it works

 - data security: sensitive columns are encrypted with aes-256 before storage. each column has its own encryption key, stored separately and encrypted with a master key. data is only decrypted when an authorized user queries it
- access control: users have roles (admin/analyst/viewer) and specific permissions for tables and columns. before executing any query, the system parses the sql to determine which tables and columns are needed, then checks if the user has permission. admins can see everything, analysts see what they're granted, viewers have read-only access to public data
- audit trail: every operation is logged to an immutable audit table with timestamp, user, query text, tables accessed, and success/denied status. logs can be searched by user, table, or time range for compliance reporting
- query flow:
    1. user submits sql query
    2. system parses query to extract tables and columns
    3. checks user permissions against access control table
    4. if allowed, executes query and decrypts authorized encrypted columns
    5. if denied, logs the attempt and returns error
    6. all activity logged to audit table

I built this to demonstrate enterprise data governance patterns: separating data storage from access control, encrypting sensitive fields, and maintaining compliance audit trails. it shows how companies handle internal data securely while allowing different teams (hr, finance, analysts) to work with the same datasets but see different levels of detail.

## usage

### basic workflow
```bash
# 1. load employee data from csv
python3 src/cli.py load data/employees.csv employees --drop

# 2. encrypt sensitive columns
python3 src/cli.py secure-column employees ssn
python3 src/cli.py secure-column employees salary

# 3. create users with different roles
python3 src/cli.py add-user hr_admin password123 admin
python3 src/cli.py add-user data_analyst analyst456 analyst
python3 src/cli.py add-user intern viewer789 viewer

# 4. grant analyst specific column access
python3 src/cli.py allow data_analyst employees name
python3 src/cli.py allow data_analyst employees email
python3 src/cli.py allow data_analyst employees salary

# 5. execute queries as different users
python3 src/cli.py execute hr_admin "SELECT name, ssn FROM employees LIMIT 3"
# ✓ admin sees decrypted ssn: 111-22-3333

python3 src/cli.py execute data_analyst "SELECT name, salary FROM employees"
# ✓ analyst sees allowed columns

python3 src/cli.py execute data_analyst "SELECT name, ssn FROM employees"
# ✗ insufficient permissions (analyst cannot see ssn)

# 6. view audit logs
python3 src/cli.py logs data_analyst --limit 10
python3 src/cli.py logs-table employees --limit 10
python3 src/cli.py logs-recent --limit 20
```

### all commands
```bash
# data management
python3 src/cli.py load <csv_file> <table_name> [--drop]
python3 src/cli.py secure-column <table> <column>
python3 src/cli.py list-tables
python3 src/cli.py describe <table>

# user management
python3 src/cli.py add-user <username> <password> <role>
python3 src/cli.py list-users

# access control
python3 src/cli.py allow <username> <table> [column]
python3 src/cli.py deny <username> <table> [column]
python3 src/cli.py permissions <username>

# query execution
python3 src/cli.py execute <username> "<sql_query>"
python3 src/cli.py validate <username> "<sql_query>"

# audit
python3 src/cli.py logs <username> [--limit N]
python3 src/cli.py logs-table <table> [--limit N]
python3 src/cli.py logs-recent [--limit N]
```

## project structure

securequery-analytics/
├── src/
│   ├── storage/      # postgresql connection and schema
│   ├── security/     # column encryption with fernet
│   ├── access/       # user auth and rbac
│   ├── engine/       # sql parsing and execution
│   ├── compliance/   # audit logging
│   ├── pipeline/     # csv ingestion
│   └── cli.py        # command-line interface
├── data/             # sample csv files
└── tests/            # module tests


## skills demonstrated

- sql database design (normalization, transactions, indexing)
- python backend architecture (modular design, error handling)
- data security patterns (encryption, access control, key management)
- compliance systems (audit trails, access logging)
- data engineering (etl, schema inference, validation)