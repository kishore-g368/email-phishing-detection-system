import sqlite3
from datetime import datetime


# ==================================================
# DATABASE FILE
# ==================================================

DATABASE = "phishing_history.db"


# ==================================================
# DATABASE CONNECTION
# ==================================================

def get_connection():
    return sqlite3.connect(DATABASE)


# ==================================================
# CREATE DATABASE TABLES
# ==================================================

def create_database():

    connection = get_connection()
    cursor = connection.cursor()


    # ------------------------------------------------
    # SCAN HISTORY TABLE
    # ------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_time TEXT,
            email_text TEXT,
            ml_result TEXT,
            ml_score REAL,
            url_risk TEXT,
            final_result TEXT,
            final_risk TEXT,
            final_score REAL
        )
    """)


    # ------------------------------------------------
    # USERS TABLE
    # ------------------------------------------------

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)


    # ------------------------------------------------
    # CREATE DEMO USER
    # ------------------------------------------------

    cursor.execute(
        "SELECT * FROM users WHERE email = ?",
        ("kishore@example.com",)
    )

    user = cursor.fetchone()


    if user is None:

        cursor.execute("""
            INSERT INTO users (email, password)
            VALUES (?, ?)
        """, (
            "kishore@example.com",
            "Kishore@123"
        ))


    connection.commit()
    connection.close()


# ==================================================
# CHECK LOGIN
# ==================================================

def check_login(email, password):

    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute("""
        SELECT id, email
        FROM users
        WHERE email = ? AND password = ?
    """, (
        email,
        password
    ))


    user = cursor.fetchone()

    connection.close()


    return user


# ==================================================
# SAVE EMAIL SCAN
# ==================================================

def save_scan(
    email_text,
    ml_result,
    ml_score,
    url_risk,
    final_result,
    final_risk,
    final_score
):

    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute("""
        INSERT INTO scans (
            scan_time,
            email_text,
            ml_result,
            ml_score,
            url_risk,
            final_result,
            final_risk,
            final_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        email_text,
        ml_result,
        ml_score,
        url_risk,
        final_result,
        final_risk,
        final_score
    ))


    connection.commit()
    connection.close()


# ==================================================
# GET SCAN HISTORY
# ==================================================

def get_scan_history():

    connection = get_connection()
    cursor = connection.cursor()


    cursor.execute("""
        SELECT
            id,
            scan_time,
            ml_result,
            ml_score,
            url_risk,
            final_result,
            final_risk,
            final_score
        FROM scans
        ORDER BY id DESC
    """)


    scans = cursor.fetchall()

    connection.close()


    return scans


# ==================================================
# GET DASHBOARD STATISTICS
# ==================================================

def get_scan_statistics():

    connection = get_connection()
    cursor = connection.cursor()


    # Total scans
    cursor.execute(
        "SELECT COUNT(*) FROM scans"
    )

    total = cursor.fetchone()[0]


    # Phishing
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE final_result = 'PHISHING'
    """)

    phishing = cursor.fetchone()[0]


    # Suspicious
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE final_result = 'SUSPICIOUS'
    """)

    suspicious = cursor.fetchone()[0]


    # Legitimate
    cursor.execute("""
        SELECT COUNT(*)
        FROM scans
        WHERE final_result = 'LEGITIMATE'
    """)

    legitimate = cursor.fetchone()[0]


    connection.close()


    return (
        total,
        phishing,
        suspicious,
        legitimate
    )