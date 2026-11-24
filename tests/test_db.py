import shutil
import sqlite3
import pytest
from src.db import get_db_connection, execute_query_safe, get_schema_ddl

def test_read_only_authorizer_blocks_mutation(tmp_path):
    """টেস্ট ১: রিড-অনলি মোডে DROP TABLE চালালে ডেটাবেজ লেভেলে আটকায় কি না"""
    db_file = str(tmp_path / "test.db")
    conn_w = sqlite3.connect(db_file)
    conn_w.execute("CREATE TABLE sample (id INT, val TEXT);")
    conn_w.execute("INSERT INTO sample VALUES (1, 'data');")
    conn_w.commit()
    conn_w.close()
    
    conn_ro = get_db_connection(db_path=db_file, read_only=True)
    rows, cols = execute_query_safe(conn_ro, "SELECT * FROM sample;")
    assert len(rows) == 1
    assert cols == ["id", "val"]
    
    # DROP TABLE চালালে DatabaseError থ্রো করতে হবে
    with pytest.raises(sqlite3.DatabaseError):
        execute_query_safe(conn_ro, "DROP TABLE sample;")
    conn_ro.close()

def test_authorizer_blocks_email_exfiltration(tmp_path):
    """টেস্ট ২: SELECT * চালালেও Authorizer গোপন email কলাম ব্লক করে কি না"""
    db_file = str(tmp_path / "test_cust.db")
    conn_w = sqlite3.connect(db_file)
    conn_w.execute("CREATE TABLE customers (id INT, name TEXT, email TEXT);")
    conn_w.execute("INSERT INTO customers VALUES (1, 'John', 'john@example.com');")
    conn_w.commit()
    conn_w.close()
    
    conn_ro = get_db_connection(db_path=db_file, read_only=True)
    # email কলাম থাকায় এই কোডটি ব্লক হতে বাধ্য
    with pytest.raises(sqlite3.DatabaseError):
        execute_query_safe(conn_ro, "SELECT * FROM customers;")
    
    # সাধারণ কলাম অ্যাক্সেস করলে সফল হবে
    rows, cols = execute_query_safe(conn_ro, "SELECT id, name FROM customers;")
    assert len(rows) == 1
    assert cols == ["id", "name"]
    conn_ro.close()

def test_physical_file_read_only_defense_in_depth(tmp_path):
    """টেস্ট ৩: আসল ecommerce.db ফাইলে ক্ষতিকর কুয়েরি চালালে ডেটা অক্ষত থাকে কি না"""
    src_db = "data/ecommerce.db"
    dest_db = str(tmp_path / "ecommerce_copy.db")
    shutil.copyfile(src_db, dest_db)
    
    conn_ro = get_db_connection(db_path=dest_db, read_only=True)
    rows, _ = execute_query_safe(conn_ro, "SELECT count(*) as c FROM orders;")
    assert rows[0]["c"] > 0
    
    # DROP এবং INSERT দুটোই ব্লক হবে
    with pytest.raises(sqlite3.DatabaseError):
        execute_query_safe(conn_ro, "DROP TABLE orders;")
        
    with pytest.raises(sqlite3.DatabaseError):
        execute_query_safe(conn_ro, "INSERT INTO categories (category_name, department) VALUES ('Hacked', 'Hacked');")
        
    conn_ro.close()
    
    # ডিস্কে ডেটা আগের মতোই আছে কি না যাচাই
    verify_conn = sqlite3.connect(dest_db)
    cur = verify_conn.cursor()
    cur.execute("SELECT count(*) FROM orders;")
    assert cur.fetchone()[0] == rows[0]["c"]
    verify_conn.close()

def test_progress_handler_timeout():
    """টেস্ট ৪: অসীম লুপ কোয়েরি দিলে ৫০ মিলিসেকেন্ডে টাইমআউট আটকায় কি না"""
    conn = get_db_connection(in_memory_clone=True)
    with pytest.raises(sqlite3.OperationalError):
        execute_query_safe(
            conn,
            "WITH RECURSIVE r(i) AS (VALUES(0) UNION ALL SELECT i+1 FROM r) SELECT count(*) FROM r;",
            timeout_ms=50
        )
    conn.close()

def test_schema_ddl_includes_distinct_values(tmp_path):
    """টেস্ট ৫: স্কিমার সাথে DELIVERED এবং delivered ডিস্টিঙ্কট ভ্যালু যুক্ত হয় কি না"""
    db_file = str(tmp_path / "test_distinct.db")
    conn = sqlite3.connect(db_file)
    conn.execute("CREATE TABLE orders (id INT, status TEXT);")
    conn.execute("INSERT INTO orders VALUES (1, 'DELIVERED'), (2, 'delivered'), (3, 'SHIPPED');")
    conn.commit()
    ddl = get_schema_ddl(conn, include_distinct_values=True)
    assert "DELIVERED" in ddl
    assert "delivered" in ddl
    conn.close()