import sqlite3
import hashlib
import datetime
import time

conn = sqlite3.connect("userdata.db")
cur = conn.cursor()
cur.execute("drop table if exists userdata;")
cur.execute("""
CREATE TABLE IF NOT EXISTS userdata (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username VARCHAR(255) NOT NULL , 
    password VARCHAR(255) NOT NULL ,
    role VARCHAR,
    phone_number VARCHAR(255),
    mobile_number VARCHAR(255),
    national_num VARCHAR(255),
    address VARCHAR(255),
    public_key VARCHAR,
    session_key VARCHAR,
    CONSTRAINT public_key_unique UNIQUE (public_key)
    CONSTRAINT session_key_unique UNIQUE (session_key)
) 
""")

# connection = sqlite3.connect("admindata.db")
# cursor = connection.cursor()
cur.execute("drop table if exists admindata;")
cur.execute("""
CREATE TABLE IF NOT EXISTS admindata (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    user_name VARCHAR NOT NULL ,
    key_role VARCHAR(6) NOT NULL , 
    CONSTRAINT key_role_unique UNIQUE (key_role)
    CONSTRAINT user_name_unique UNIQUE (user_name)
) 
""")

cur.execute("drop table if exists doctors_csr_verification;")
cur.execute("""
CREATE TABLE IF NOT EXISTS doctors_csr_verification (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    user_name VARCHAR NOT NULL ,
    code VARCHAR(6) NOT NULL , 
    CONSTRAINT key_role_unique UNIQUE (code)
    CONSTRAINT user_name_unique UNIQUE (user_name)
) 
""")

cur.execute("drop table if exists files_verifications;")
cur.execute("""
CREATE TABLE IF NOT EXISTS files_verifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    is_success BOOLEAN,
    created_at timestamp,
    file_path VARCHAR,
    user_id INTEGER  NOT NULL,
    FOREIGN KEY (user_id)
    REFERENCES userdata (id) ON DELETE CASCADE
) 
""")

cur.execute("drop table if exists student_projects;")
cur.execute("""
CREATE TABLE IF NOT EXISTS student_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    projects VARCHAR,
    user_id INTEGER  NOT NULL,
    created_at timestamp,
    FOREIGN KEY (user_id)
    REFERENCES userdata (id) ON DELETE CASCADE
) 
""")

cur.execute("drop table if exists dr_crt;")
cur.execute("""
CREATE TABLE IF NOT EXISTS dr_crt (
    id INTEGER PRIMARY KEY AUTOINCREMENT, 
    user_id INTEGER  NOT NULL,
    crt_t VARCHAR,
    created_at timestamp,
    FOREIGN KEY (user_id)
    REFERENCES userdata (id) ON DELETE CASCADE
) 
""")

# password has to be in bytes, so we encode itg
# we can make it encode(utf-8) if we need
username1, password1 = "sham", hashlib.sha256(
    "shampassword".encode()).hexdigest()
username2, password2 = "Philip", hashlib.sha256(
    "philip123".encode()).hexdigest()

user2public = """-----BEGIN RSA PUBLIC KEY-----
MIGJAoGBAIwZCLejPXdczN/dNSgLMQSQORMpxQ7knmCz9qeeTFx/zFehqg/Z03s7
yNP10EhkRQP1bt0u594v8Y6Z2Q5EH/Brl7lLVx9pIbf/kQx2iIIU+rxh2qkPuUIY
/Ao2S8++BmWUx+mVCZPnO/GOggnY9LHy7c6oQgr0XG+GF/kifs75AgMBAAE=
-----END RSA PUBLIC KEY-----"""

cur.executemany("INSERT INTO admindata(user_name , key_role) VALUES (? ,?)",
                [
                    ("omar", "12345"),
                    ("fadi", "67890"),
                    ("wael", "67590")
                ]
                )
cur.executemany("INSERT INTO userdata(username , password,public_key) VALUES (? , ?, ?)",
                [
                    (username1, password1, "dsa"),
                    (username2, password2, "".join(line.strip()
                     for line in user2public.splitlines()))
                ])
cur.executemany("INSERT INTO doctors_csr_verification(user_name , code) VALUES (? ,?)",
                [
                    ("omar", "12345"),
                    ("fadi", "67890"),
                    ("wael", "67590")
                ]
                )
conn.commit()
