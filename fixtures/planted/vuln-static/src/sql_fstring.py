# FALHA PLANTADA (P-004): SQL com f-string e dado da requisição. CWE-89.
def find_by_id(cursor, request):
    cursor.execute(f"SELECT * FROM users WHERE id = {request.args['id']}")
    return cursor.fetchall()
