import sqlite3
import os

try:
    from pysqlcipher3 import dbapi2 as sqlcipher
except ImportError:
    import sqlite3 as sqlcipher

def test():
    # 1. Create a plaintext DB
    if os.path.exists("plain.db"): os.remove("plain.db")
    conn_plain = sqlcipher.connect("plain.db")
    conn_plain.execute("CREATE TABLE test (id int)")
    conn_plain.close()

    # 2. Create an encrypted DB
    if os.path.exists("enc.db"): os.remove("enc.db")
    conn_enc = sqlcipher.connect("enc.db")
    conn_enc.execute("PRAGMA key = 'mykey'")
    conn_enc.execute("CREATE TABLE enc_test (id int)")

    # 3. Try to attach plaintext DB without KEY ''
    try:
        conn_enc.execute("ATTACH DATABASE 'plain.db' AS plain1")
        conn_enc.execute("SELECT * FROM plain1.test")
        print("Attach without KEY '' WORKED!")
    except Exception as e:
        print("Attach without KEY '' FAILED:", e)

    # 4. Try to attach plaintext DB with KEY ''
    try:
        conn_enc.execute("ATTACH DATABASE 'plain.db' KEY '' AS plain2")
        conn_enc.execute("SELECT * FROM plain2.test")
        print("Attach with KEY '' WORKED!")
    except Exception as e:
        print("Attach with KEY '' FAILED:", e)

test()
