from mysql_connector import get_db


def reconcile_single_row(cursor, internal_row):
    assignment_id = internal_row["assignment_id"]
    internal_total = internal_row["total"]

    # Fetch agency totals
    cursor.execute("""
        SELECT COALESCE(SUM(total), 0) AS total_sum
        FROM agency_data
        WHERE assignment_id = %s
    """, (assignment_id,))

    row = cursor.fetchone()
    agency_sum = row["total_sum"] if row else 0

    difference = agency_sum - internal_total

    # Determine status
    if difference == 0:
        status = "Matched"
    else:
        status = "Matched" if agency_sum > internal_total else "Pending"

    outstanding = round(difference, 2)

    # Update
    cursor.execute("""
        UPDATE internal_data
        SET status = %s,
            outstanding = %s
        WHERE assignment_id = %s
    """, (status, outstanding, assignment_id))

    return assignment_id   # 👈 return ONLY ID so we can fetch full rows later


def reconcile_all():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 1️⃣ Check if NULL rows exist
    cursor.execute("""
        SELECT assignment_id, total
        FROM internal_data
        WHERE status IS NULL
    """)
    null_rows = cursor.fetchall()

    # 2️⃣ Fetch pending rows (needed in both cases)
    cursor.execute("""
        SELECT assignment_id, total
        FROM internal_data
        WHERE status = 'Pending'
    """)
    pending_rows = cursor.fetchall()

    rows_to_reconcile = []

    if len(null_rows) > 0:
        rows_to_reconcile = null_rows + pending_rows
    else:
        cursor.execute("""
            SELECT MAX(created_at) AS latest_date
            FROM internal_data
        """)
        latest_date = cursor.fetchone()["latest_date"]

        latest_date_rows = []
        if latest_date:
            cursor.execute("""
                SELECT assignment_id, total
                FROM internal_data
                WHERE created_at = %s
            """, (latest_date,))
            latest_date_rows = cursor.fetchall()

        rows_to_reconcile = latest_date_rows + pending_rows

    # Run reconciliation
    assignment_ids = []
    for row in rows_to_reconcile:
        assignment_ids.append(reconcile_single_row(cursor, row))

    conn.commit()

    if not assignment_ids:
        return []

    # 🔥 Fetch full rows of reconciled records
    format_str = ",".join(["%s"] * len(assignment_ids))
    cursor.execute(f"""
        SELECT *
        FROM internal_data
        WHERE assignment_id IN ({format_str})
    """, assignment_ids)

    return cursor.fetchall()


def reconcile_by_date(start_date, end_date):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT assignment_id, total
        FROM internal_data
        WHERE (status IS NULL OR status = 'Pending')
          AND shift_date BETWEEN %s AND %s
    """, (start_date, end_date))

    rows = cursor.fetchall()

    assignment_ids = []
    for row in rows:
        assignment_ids.append(reconcile_single_row(cursor, row))

    conn.commit()

    if not assignment_ids:
        return []

    # 🔥 Fetch full rows of reconciled records
    format_str = ",".join(["%s"] * len(assignment_ids))
    cursor.execute(f"""
        SELECT *
        FROM internal_data
        WHERE assignment_id IN ({format_str})
    """, assignment_ids)

    return cursor.fetchall()


def reconcile_by_date_and_facility(start_date, end_date,facility):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT assignment_id, total
        FROM internal_data
        WHERE (status IS NULL OR status = 'Pending')
          AND shift_date BETWEEN %s AND %s AND facility = %s
    """, (start_date, end_date,facility))

    rows = cursor.fetchall()

    assignment_ids = []
    for row in rows:
        assignment_ids.append(reconcile_single_row(cursor, row))

    conn.commit()

    if not assignment_ids:
        return []

    # 🔥 Fetch full rows of reconciled records
    format_str = ",".join(["%s"] * len(assignment_ids))
    cursor.execute(f"""
        SELECT *
        FROM internal_data
        WHERE assignment_id IN ({format_str})
    """, assignment_ids)

    return cursor.fetchall()