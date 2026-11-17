# Gêmea limpa de P-004: o valor vai como parâmetro do driver.
def find_by_id(cursor, request):
    cursor.execute("SELECT * FROM users WHERE id = %s", (request.args["id"],))
    return cursor.fetchall()
