import sqlite3
conn = sqlite3.connect('packets.db')
conn.execute('UPDATE ip_aliases SET name="", description="" WHERE name="자동 감지됨"')
conn.commit()
print("done")
