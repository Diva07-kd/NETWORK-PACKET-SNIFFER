import streamlit as st
import pandas as pd
import sqlite3
import time

# --- Page Configuration ---
st.set_page_config(
    page_title="Live Network Monitor",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Main App ---
st.title("Live Network Traffic Monitor 🌐")

def get_data():
    """Fetches the latest 1000 packets from the SQLite database."""
    try:
        # Use 'with' to ensure the connection is closed properly
        with sqlite3.connect("traffic.db") as conn:
            # Read data into a pandas DataFrame
            df = pd.read_sql_query("SELECT * FROM packets ORDER BY timestamp DESC LIMIT 1000", conn)
        return df
    except sqlite3.Error as e:
        st.error(f"Database error: {e}")
        return pd.DataFrame() # Return an empty DataFrame on error

# Create a placeholder to refresh content in
placeholder = st.empty()

# --- Main Loop to Refresh Data ---
while True:
    df = get_data()
    
    with placeholder.container():
        st.header("Latest Packets Captured")
        # Display the main data table
        st.dataframe(df, use_container_width=True)

        # Create two columns for charts
        col1, col2 = st.columns(2)
        
        with col1:
            st.header("Top 10 Source IPs")
            if not df.empty and 'src' in df.columns:
                st.bar_chart(df['src'].value_counts().head(10))
            else:
                st.write("No source IP data to display.")
        
        with col2:
            st.header("Protocol Distribution")
            if not df.empty and 'proto' in df.columns:
                # Ensure protocol is treated as a string for counting
                st.bar_chart(df['proto'].astype(str).value_counts())
            else:
                st.write("No protocol data to display.")
            
    # Wait for 5 seconds before refreshing the data
    time.sleep(5)