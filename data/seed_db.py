import os
import sqlite3
import random
from datetime import datetime, timedelta

def seed_database(db_path: str = "data/ecommerce.db", total_records: int = 15000) -> None:
    """
    Seeds a synthetic enterprise e-commerce database with ~15,000 relational records
    containing realistic anomalies (mixed casing, nulls, orphaned items).
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    if os.path.exists(db_path):
        os.remove(db_path)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 1. Create Tables (Relational Schema)
    cursor.execute("""
    CREATE TABLE categories (
        category_id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_name TEXT NOT NULL,
        department TEXT NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE products (
        product_id INTEGER PRIMARY KEY AUTOINCREMENT,
        category_id INTEGER,
        product_name TEXT NOT NULL,
        cost REAL NOT NULL,
        retail_price REAL NOT NULL,
        stock_quantity INTEGER NOT NULL,
        FOREIGN KEY (category_id) REFERENCES categories (category_id)
    );
    """)

    cursor.execute("""
    CREATE TABLE customers (
        customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        city TEXT NOT NULL,
        country TEXT NOT NULL,
        signup_date TEXT NOT NULL,
        is_active INTEGER NOT NULL
    );
    """)

    cursor.execute("""
    CREATE TABLE orders (
        order_id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        order_date TEXT NOT NULL,
        status TEXT NOT NULL,
        total_amount REAL NOT NULL,
        FOREIGN KEY (customer_id) REFERENCES customers (customer_id)
    );
    """)

    cursor.execute("""
    CREATE TABLE order_items (
        item_id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        unit_price REAL NOT NULL,
        discount_pct REAL,
        FOREIGN KEY (order_id) REFERENCES orders (order_id),
        FOREIGN KEY (product_id) REFERENCES products (product_id)
    );
    """)

    cursor.execute("""
    CREATE TABLE payments (
        payment_id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id INTEGER NOT NULL,
        payment_method TEXT NOT NULL,
        payment_status TEXT NOT NULL,
        payment_date TEXT NOT NULL,
        FOREIGN KEY (order_id) REFERENCES orders (order_id)
    );
    """)

    # 2. Seed Categories
    categories = [
        ("Smartphones", "Electronics"),
        ("Laptops", "Electronics"),
        ("Men's Apparel", "Clothing"),
        ("Women's Apparel", "Clothing"),
        ("Kitchenware", "Home & Living"),
        ("Furniture", "Home & Living"),
        ("Fitness Equipment", "Sports"),
        ("Books & Media", "Entertainment")
    ]
    cursor.executemany("INSERT INTO categories (category_name, department) VALUES (?, ?);", categories)

    # 3. Seed Products (Including 20% intentional orphaned products with NULL category_id)
    products = []
    for i in range(1, 151):
        cat_id = random.choice([1, 2, 3, 4, 5, 6, 7, 8, None, None]) # Orphan items trap
        cost = round(random.uniform(10.0, 500.0), 2)
        price = round(cost * random.uniform(1.2, 2.0), 2)
        stock = random.randint(0, 250)
        pname = f"Product-{i:03d} {random.choice(['Pro', 'Plus', 'Elite', 'Classic', 'Lite'])}"
        products.append((cat_id, pname, cost, price, stock))
    cursor.executemany(
        "INSERT INTO products (category_id, product_name, cost, retail_price, stock_quantity) VALUES (?, ?, ?, ?, ?);",
        products
    )

    # 4. Seed Customers
    cities = ["Dhaka", "Chittagong", "Sylhet", "Rajshahi", "Khulna", "New York", "London", "Toronto"]
    countries = ["Bangladesh", "Bangladesh", "Bangladesh", "Bangladesh", "USA", "UK", "Canada"]
    customers = []
    base_date = datetime(2024, 1, 1)
    for i in range(1, 1001):
        name = f"Customer_{i:04d}"
        email = f"user_{i:04d}@example.com"
        city = random.choice(cities)
        country = random.choice(countries)
        s_date = (base_date + timedelta(days=random.randint(0, 365))).strftime("%Y-%m-%d")
        is_active = random.choice([1, 1, 1, 0])
        customers.append((name, email, city, country, s_date, is_active))
    cursor.executemany(
        "INSERT INTO customers (full_name, email, city, country, signup_date, is_active) VALUES (?, ?, ?, ?, ?, ?);",
        customers
    )

    # 5. Seed Orders, Order Items, and Payments (~15,000 relational records)
    status_choices = ["DELIVERED", "DELIVERED", "delivered", "SHIPPED", "CANCELLED", "REFUNDED"]
    payment_methods = ["BKASH", "NAGAD", "CREDIT_CARD", "PAYPAL"]
    
    orders = []
    order_items = []
    payments = []
    
    item_id_counter = 1
    payment_id_counter = 1

    for order_id in range(1, 3501):
        cust_id = random.randint(1, 1000)
        o_date = (base_date + timedelta(days=random.randint(0, 365), hours=random.randint(0, 23))).strftime("%Y-%m-%d %H:%M:%S")
        status = random.choice(status_choices)
        
        # 1 to 4 items per order
        num_items = random.randint(1, 4)
        order_total = 0.0
        
        for _ in range(num_items):
            prod_id = random.randint(1, 150)
            qty = random.randint(1, 3)
            u_price = round(random.uniform(20.0, 400.0), 2)
            # Intentional anomaly: nullable discount_pct (NULL instead of 0.0)
            discount = random.choice([None, None, 0.05, 0.10, 0.15])
            line_cost = qty * u_price * (1.0 - (discount if discount else 0.0))
            order_total += line_cost
            
            order_items.append((item_id_counter, order_id, prod_id, qty, u_price, discount))
            item_id_counter += 1
            
        orders.append((order_id, cust_id, o_date, status, round(order_total, 2)))
        
        # Payment record
        p_method = random.choice(payment_methods)
        p_status = "SUCCESS" if status in ("DELIVERED", "delivered", "SHIPPED") else ("REFUNDED" if status == "REFUNDED" else "FAILED")
        payments.append((payment_id_counter, order_id, p_method, p_status, o_date))
        payment_id_counter += 1

    cursor.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?);", orders)
    cursor.executemany("INSERT INTO order_items VALUES (?, ?, ?, ?, ?, ?);", order_items)
    cursor.executemany("INSERT INTO payments VALUES (?, ?, ?, ?, ?);", payments)

    conn.commit()
    conn.close()
    print(f"Successfully seeded database at {db_path} with:")
    print(f"- {len(categories)} categories")
    print(f"- {len(products)} products")
    print(f"- {len(customers)} customers")
    print(f"- {len(orders)} orders")
    print(f"- {len(order_items)} order items")
    print(f"- {len(payments)} payments")
    print(f"Total relational records: {len(categories) + len(products) + len(customers) + len(orders) + len(order_items) + len(payments)}")

if __name__ == "__main__":
    seed_database()