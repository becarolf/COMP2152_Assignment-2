"""
Author: Beatriz Ferreira
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

import socket
import threading
import sqlite3
import os
import platform
import datetime


print("Python Version: ", platform.python_version())
print("Operating System: ", os.name)


# This dictionary stores common port numbers and their service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}



class NetworkTool:
    def __init__(self, target):
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property and @target.setter helps control how we access private data in a class.
    # It allows the program to safely get or update the target value without directly changing the 
    # private variable.
    # This makes the code safer and easier to manage.
    @property
    def target(self):
        return self.__target
    
    @target.setter
    def target(self, value):
        if value != "":
            self.__target = value
        else: 
            print("Error: Target cannot be empty")
    
    def __del__(self):
        print("NetworkTool instance destroyed")



# Q1: How does PortScanner reuse code from NetworkTool?
# It reuses code from NetworkTool through inheritance.
# It automatically gets the target attribute, the getter and setter methods, and the destructor behavior
# from the parent class.
# This reduces repeated code and makes the program easier to organize and manage.
class PortScanner(NetworkTool):
    def __init__(self, target):
        super().__init__(target)
        self.scan_results = []
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()


    def scan_port(self, port):
        sock = None
        # Q4: What would happen without try-except here?
        # Without try-except, a socket error could stop the program while scanning a port.
        # This would be a problem if the target machine is unreachable or if a connection attempt fails unexpectedly.
        # Using try-except allows the scanner to continue checking the remaining ports instead of crashing.
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                status = "Open"
            else:
                status = "Closed"

            service_name = common_ports.get(port, "Unknown")

            self.lock.acquire()
            self.scan_results.append((port, status, service_name))
            self.lock.release()

        except socket.error as error_message:
            print(f"Error scanning port {port}: {error_message}")

        finally: 
            if sock:
                sock.close()


    def get_open_ports(self):
        return [result for result in self.scan_results if result[1] == "Open"]
    
    
    # Q2: Why do we use threading instead of scanning one port at a time?
    # We use threading so multiple ports can be scanned at the same time instead of one by one.
    # If the program scanned 1024 ports sequentially, it would take much longer to finish, especially with socket timeouts.
    # Threading makes the scanner faster and more efficient when working with large port ranges.
    def scan_range(self, start_port, end_port):
        threads = []

        for port in range(start_port, end_port + 1):
            thread = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(thread)

        for thread in threads:
            thread.start()

        for thread in threads:
            thread.join()



def save_results(target, results):
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT,
                port INTEGER,
                status TEXT,
                service TEXT,
                scan_date TEXT)
        """)

        for port, status, service in results:
            cursor.execute("""
                INSERT INTO scans (target, port, status, service, scan_date)
                VALUES(?, ?, ?, ?, ?)
            """, (target, port, status, service, str(datetime.datetime.now())))

        conn.commit()
    
    except sqlite3.Error as error_message:
        print(f"Database error: {error_message}")

    finally:
        if conn:
            conn.close()



def load_past_scans():
    conn = None
    try:
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans")
        rows = cursor.fetchall()

        if len(rows) == 0:
            print("No past scans found.")
        else:
            print("\nPast Scan History:")
            for row in rows:
                print(
                    f"ID: {row[0]}, Target: {row[1]}, Port: {row[2]}, "
                    f"Status: {row[3]}, Service: {row[4]}, Date: {row[5]}"
                )
    except sqlite3.Error:
        print("No past scans found.")

    finally:
        if conn:
            conn.close()


# ============================================================
# MAIN PROGRAM
# ============================================================
if __name__ == "__main__":

    try:
        target = input("Enter target IP address (press Enter for 127.0.0.1): ").strip()
        if target == "":
            target = "127.0.0.1"

        start_port = int(input("Enter start port (1-1024): "))
        end_port = int(input("Enter end port (1-1024): "))

        if start_port < 1 or start_port > 1024 or end_port < 1 or end_port > 1024:
            print("Port must be between 1 and 1024.")
        elif end_port < start_port:
            print("End port must be greater than or equal to start port.")
        else:
            scanner = PortScanner(target)
            print(f"\nScanning {target} from port {start_port} to {end_port}...")
            scanner.scan_range(start_port, end_port)

            open_ports = scanner.get_open_ports()

            print("\nOpen Ports:")
            if len(open_ports) == 0:
                print("No open ports found.")
            else:
                for port, status, service in open_ports:
                    print(f"Port {port} is {status} ({service})")

            print(f"\nTotal open ports found: {len(open_ports)}")

            save_results(target, scanner.scan_results)

            choice = input("\nWould you like to see past scan history? (yes/no): ").strip().lower()
            if choice == "yes":
                load_past_scans()

    except ValueError:
        print("Invalid input. Please enter a valid integer.")



# Q5: New Feature Proposal
# One useful new feature would be exporting open port scan results to a CSV or TXT file.
# This feature could use a list comprehension to filter and collect only open ports before saving them to a file.
# It would help users save and analyze scan results more easily for reporting or security purposes.