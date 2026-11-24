"""
Seed Database for ApexVault AI Multi-Tenant Platform
"""

import os
import sqlite3

def seed_apex_vault():
    os.makedirs("data", exist_ok=True)
    db_path = "data/apex_vault.db"
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE accounts (
            account_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            owner_name TEXT NOT NULL,
            account_type TEXT NOT NULL,
            balance REAL NOT NULL
        );
    """)

    c.execute("""
        CREATE TABLE customers (
            customer_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            ssn TEXT NOT NULL
        );
    """)

    c.execute("""
        CREATE TABLE transactions (
            tx_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            account_id TEXT NOT NULL,
            description TEXT NOT NULL,
            amount REAL NOT NULL,
            tx_type TEXT NOT NULL
        );
    """)

    c.execute("""
        CREATE TABLE invoices (
            invoice_id TEXT PRIMARY KEY,
            tenant_id TEXT NOT NULL,
            client_name TEXT NOT NULL,
            amount REAL NOT NULL,
            status TEXT NOT NULL
        );
    """)

    # Seed org_alpha (Alpha Corporation)
    c.execute("INSERT INTO accounts VALUES ('ACC_A1', 'org_alpha', 'Alpha Treasury Ops', 'Operating', 4850000.00)")
    c.execute("INSERT INTO accounts VALUES ('ACC_A2', 'org_alpha', 'Alpha Payroll Fund', 'Payroll', 320000.00)")
    c.execute("INSERT INTO customers VALUES ('CUST_A1', 'org_alpha', 'Alice Stark', 'alice@alphacorp.com', '+1-555-0101', '123-45-6789')")
    c.execute("INSERT INTO transactions VALUES ('TX_A1', 'org_alpha', 'ACC_A1', 'Q3 Cloud Infrastructure', -45000.00, 'DEBIT')")
    c.execute("INSERT INTO transactions VALUES ('TX_A2', 'org_alpha', 'ACC_A1', 'Client Wire Receipt', 120000.00, 'CREDIT')")
    c.execute("INSERT INTO invoices VALUES ('INV_A1', 'org_alpha', 'Acme Global', 85000.00, 'PAID')")

    # Seed org_beta (Beta Holdings)
    c.execute("INSERT INTO accounts VALUES ('ACC_B1', 'org_beta', 'Beta Secret Fund', 'Offshore', 98500000.00)")
    c.execute("INSERT INTO accounts VALUES ('ACC_B2', 'org_beta', 'Beta Reserve', 'Escrow', 14200000.00)")
    c.execute("INSERT INTO customers VALUES ('CUST_B1', 'org_beta', 'Bruce Wayne', 'bruce@betaholdings.com', '+1-555-0999', '987-65-4321')")
    c.execute("INSERT INTO transactions VALUES ('TX_B1', 'org_beta', 'ACC_B1', 'Confidential Acquisition', -15000000.00, 'DEBIT')")
    c.execute("INSERT INTO invoices VALUES ('INV_B1', 'org_beta', 'LexCorp Systems', 5000000.00, 'PENDING')")

    conn.commit()
    conn.close()
    print("ApexVault database successfully initialized at data/apex_vault.db")

if __name__ == "__main__":
    seed_apex_vault()
