import sqlite3

# Connect to the database and enable multi-threaded access
conn = sqlite3.connect("traffic.db", check_same_thread=False)
cur = conn.cursor()

# Create the packets table if it doesn't already exist
cur.execute('''
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL,
        src TEXT,
        dst TEXT,
        proto TEXT,
        sport INTEGER,
        dport INTEGER,
        length INTEGER
    );''')
conn.commit()

def insert_packet(info):
    """Inserts a single packet record into the database."""
    cur.execute('''
        INSERT INTO packets (timestamp, src, dst, proto, sport, dport, length)
        VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (info['timestamp'], info['src'], info['dst'], info['proto'],
         info['sport'], info['dport'], info['length']))
    conn.commit()

def insert_packets_batch(packet_batch):
    """
    Inserts a batch of packet records into the database using executemany for efficiency.
    """
    sql_insert_query = '''
        INSERT INTO packets (timestamp, src, dst, proto, sport, dport, length)
        VALUES (?, ?, ?, ?, ?, ?, ?)'''
    
    # Transform the list of dictionaries into a list of tuples
    # The order of values in the tuple must match the columns in the query
    data_to_insert = [
        (
            pkt.get('timestamp'), pkt.get('src'), pkt.get('dst'),
            pkt.get('proto'), pkt.get('sport'), pkt.get('dport'),
            pkt.get('length')
        ) for pkt in packet_batch
    ]
    
    # Execute the query for all items in the list and commit once
    cur.executemany(sql_insert_query, data_to_insert)
    conn.commit()