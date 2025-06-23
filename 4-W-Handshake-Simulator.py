import os
import hashlib
import hmac
import binascii
import struct
import re

class WPA2HandshakeSimulator:
    """
    WPA2 4-Way Handshake Simulator Class
    
    This class simulates the complete WPA2 4-way handshake process used in
    wireless network authentication. It demonstrates how the Access Point (AP)
    and client establish secure communication through key derivation and exchange.
    """
    
    def __init__(self):
        """Initialize the simulator with empty key values"""
        self.pmk = None          # Pairwise Master Key
        self.ptk = None          # Pairwise Transient Key
        self.gtk = None          # Group Temporal Key
        self.anonce = None       # Access Point Nonce
        self.snonce = None       # Station (Client) Nonce
        
    def generate_nonce(self):
        """
        Generate a cryptographically secure 32-byte random nonce
        
        Returns:
            bytes: 32-byte random value used for key derivation
        """
        return os.urandom(32)
    
    def generate_gtk(self):
        """
        Generate a Group Temporal Key for broadcast/multicast traffic
        
        Returns:
            bytes: 32-byte GTK for group communication encryption
        """
        return os.urandom(32)
    
    def derive_pmk(self, password, ssid):
        """
        Derive Pairwise Master Key using PBKDF2-SHA1
        
        The PMK is derived from the network password and SSID using PBKDF2
        with 4096 iterations as specified in the WPA2 standard.
        
        Args:
            password (str): Network password/passphrase
            ssid (str): Network SSID (Service Set Identifier)
            
        Returns:
            bytes: 32-byte PMK derived from password and SSID
        """
        return hashlib.pbkdf2_hmac('sha1', password.encode('utf-8'), ssid.encode('utf-8'), 4096, 32)
    
    def derive_ptk(self, pmk, anonce, snonce, ap_mac, client_mac):
        """
        Derive Pairwise Transient Key using PRF-512
        
        The PTK is derived from PMK, both nonces, and MAC addresses using
        the Pseudo-Random Function as defined in IEEE 802.11 standard.
        
        Args:
            pmk (bytes): Pairwise Master Key
            anonce (bytes): Access Point nonce
            snonce (bytes): Station nonce
            ap_mac (str): Access Point MAC address
            client_mac (str): Client MAC address
            
        Returns:
            bytes: 64-byte PTK containing KCK, KEK, and TK
        """
        # Convert MAC addresses from string format to bytes
        ap_mac_bytes = bytes.fromhex(ap_mac.replace(':', ''))
        client_mac_bytes = bytes.fromhex(client_mac.replace(':', ''))
        
        # Construct PTK input according to IEEE 802.11 standard
        # Format: "Pairwise key expansion" + null + min(MAC1,MAC2) + max(MAC1,MAC2) + min(Nonce1,Nonce2) + max(Nonce1,Nonce2)
        ptk_input = (
            b"Pairwise key expansion" + b"\0" +
            min(ap_mac_bytes, client_mac_bytes) +
            max(ap_mac_bytes, client_mac_bytes) +
            min(anonce, snonce) +
            max(anonce, snonce)
        )
        
        # Generate PTK using PRF-512 (4 iterations of HMAC-SHA1)
        ptk = b""
        for i in range(4):
            ptk += hmac.new(pmk, ptk_input + struct.pack("B", i), hashlib.sha1).digest()
        
        return ptk[:64]  # Return first 64 bytes (512 bits)
    
    def calculate_mic(self, key, data):
        """
        Calculate Message Integrity Code using HMAC-SHA1
        
        The MIC ensures message integrity and authenticity during handshake.
        Uses the first 16 bytes of PTK as the key.
        
        Args:
            key (bytes): PTK or portion of PTK to use as HMAC key
            data (str): Message data to authenticate
            
        Returns:
            str: 32-character hexadecimal MIC value
        """
        return hmac.new(key[:16], data.encode('utf-8'), hashlib.sha1).hexdigest()[:32]
    
    def hexlify(self, data):
        """
        Convert binary data to uppercase hexadecimal string
        
        Args:
            data (bytes): Binary data to convert
            
        Returns:
            str: Uppercase hexadecimal representation
        """
        return binascii.hexlify(data).decode().upper()
    
    def sanitize_mac_address(self, mac_address):
        """
        Sanitize and validate MAC address format
        
        Accepts various MAC address formats and converts them to standard
        colon-separated uppercase format (XX:XX:XX:XX:XX:XX).
        
        Args:
            mac_address (str): MAC address in various formats
            
        Returns:
            str: Standardized MAC address or None if invalid
        """
        if not mac_address:
            return None
            
        # Remove all non-alphanumeric characters and convert to uppercase
        clean_mac = re.sub(r'[^0-9A-Fa-f]', '', mac_address.upper())
        
        # Check if we have exactly 12 hex characters
        if len(clean_mac) != 12 or not re.match(r'^[0-9A-F]{12}$', clean_mac):
            return None
            
        # Format as standard colon-separated MAC address
        formatted_mac = ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2))
        
        return formatted_mac
    
    def pause_for_user(self, message="Press Enter to continue to next stage..."):
        """
        Pause execution and wait for user input
        
        Args:
            message (str): Message to display to user
        """
        input(f"\n{message}")
        print()
    
    def simulate_handshake(self, ssid, password, client_mac, client_mac_original, ap_mac, ap_mac_original):
        """
        Simulate the complete WPA2 4-way handshake process
        
        This method demonstrates all four messages of the handshake:
        1. AP -> Client: ANonce
        2. Client -> AP: SNonce + MIC
        3. AP -> Client: GTK + MIC  
        4. Client -> AP: ACK
        
        Args:
            ssid (str): Network SSID
            password (str): Network password
            client_mac (str): Sanitized client MAC address
            client_mac_original (str): Original client MAC input
            ap_mac (str): Sanitized AP MAC address  
            ap_mac_original (str): Original AP MAC input
            
        Returns:
            bool: True if handshake completed successfully, False otherwise
        """
        print("=" * 70)
        print("WPA2 4-Way Handshake Simulation - Network Parameters")
        print("=" * 70)
        print(f"Network SSID: {ssid}")
        print(f"Client MAC (Original Input): {client_mac_original}")
        print(f"Client MAC (Sanitized): {client_mac}")
        print(f"AP MAC (Original Input): {ap_mac_original}")
        print(f"AP MAC (Sanitized): {ap_mac}")
        print("=" * 70)
        
        self.pause_for_user("Press Enter to begin PMK derivation...")
        
        # Pre-handshake: PMK derivation from password and SSID
        print("STAGE 0: PRE-HANDSHAKE KEY DERIVATION")
        print("-" * 40)
        print("Deriving Pairwise Master Key (PMK) from network password and SSID...")
        print("Using PBKDF2-SHA1 with 4096 iterations as per WPA2 standard")
        
        self.pmk = self.derive_pmk(password, ssid)
        print(f"PMK (32 bytes): {self.hexlify(self.pmk)}")
        print("PMK derivation completed successfully")
        
        self.pause_for_user("Press Enter to proceed to Message 1...")
        
        # Message 1: AP sends ANonce to Client
        print("STAGE 1: MESSAGE 1 - AP INITIATES HANDSHAKE")
        print("-" * 50)
        print("Access Point (AP) generates and sends ANonce to Client")
        print("This begins the 4-way handshake authentication process")
        
        self.anonce = self.generate_nonce()
        print(f"ANonce (32 bytes): {self.hexlify(self.anonce)}")
        print("Message 1: AP -> Client [ANonce]")
        print("Client receives ANonce from AP")
        
        self.pause_for_user("Press Enter to proceed to Message 2...")
        
        # Message 2: Client generates SNonce and derives PTK
        print("STAGE 2: MESSAGE 2 - CLIENT RESPONSE")
        print("-" * 40)
        print("Client generates SNonce and derives PTK for secure communication")
        print("Client will send SNonce with MIC for message authentication")
        
        self.snonce = self.generate_nonce()
        print(f"SNonce (32 bytes): {self.hexlify(self.snonce)}")
        
        # Client derives PTK using PMK, nonces, and MAC addresses
        print("\nDeriving Pairwise Transient Key (PTK)...")
        print("PTK = PRF-512(PMK, ANonce, SNonce, AP_MAC, Client_MAC)")
        
        self.ptk = self.derive_ptk(self.pmk, self.anonce, self.snonce, ap_mac, client_mac)
        print(f"PTK (64 bytes): {self.hexlify(self.ptk)}")
        
        # Client calculates MIC for message 2 authentication
        message2_data = f"Message2_{self.hexlify(self.snonce)}"
        mic_client_msg2 = self.calculate_mic(self.ptk, message2_data)
        print(f"\nMIC for Message 2: {mic_client_msg2}")
        print("Message 2: Client -> AP [SNonce + MIC]")
        
        self.pause_for_user("Press Enter to proceed to Message 3...")
        
        # Message 3: AP derives PTK, generates GTK, and sends to Client
        print("STAGE 3: MESSAGE 3 - AP SENDS GROUP KEY")
        print("-" * 45)
        print("AP derives PTK independently and verifies client authenticity")
        print("AP generates GTK for broadcast/multicast traffic encryption")
        
        # AP derives PTK (should match client's PTK)
        ptk_ap = self.derive_ptk(self.pmk, self.anonce, self.snonce, ap_mac, client_mac)
        print(f"AP PTK (64 bytes): {self.hexlify(ptk_ap)}")
        
        # Verify PTK consistency between AP and Client
        print("\nVerifying PTK consistency...")
        if self.ptk == ptk_ap:
            print("SUCCESS: AP and Client have derived identical PTK")
            print("Both parties can now generate matching encryption keys")
        else:
            print("ERROR: PTK mismatch between AP and Client")
            print("Handshake cannot proceed - authentication failed")
            return False
        
        # AP generates GTK for group communication
        print("\nGenerating Group Temporal Key (GTK)...")
        self.gtk = self.generate_gtk()
        print(f"GTK (32 bytes): {self.hexlify(self.gtk)}")
        
        # AP calculates MIC for message 3 containing GTK
        message3_data = f"Message3_{self.hexlify(self.gtk)}"
        mic_ap_msg3 = self.calculate_mic(self.ptk, message3_data)
        print(f"MIC for Message 3: {mic_ap_msg3}")
        print("Message 3: AP -> Client [GTK + MIC]")
        
        self.pause_for_user("Press Enter to proceed to Message 4...")
        
        # Message 4: Client verifies MIC and sends acknowledgment
        print("STAGE 4: MESSAGE 4 - CLIENT ACKNOWLEDGMENT")
        print("-" * 45)
        print("Client verifies MIC from Message 3 to ensure GTK integrity")
        print("Client installs keys and sends final acknowledgment to AP")
        
        # Client verifies MIC from AP's message 3
        mic_client_verify = self.calculate_mic(self.ptk, message3_data)
        print(f"Client MIC Verification: {mic_client_verify}")
        
        print("\nVerifying Message 3 integrity...")
        if mic_ap_msg3 == mic_client_verify:
            print("SUCCESS: Message 3 MIC verification passed")
            print("GTK received securely and authenticated")
        else:
            print("ERROR: MIC verification failed")
            print("Message integrity compromised - handshake aborted")
            return False
        
        # Client sends final acknowledgment
        ack_data = "Handshake_Complete_ACK"
        mic_ack = self.calculate_mic(self.ptk, ack_data)
        print(f"\nACK MIC: {mic_ack}")
        print("Message 4: Client -> AP [ACK]")
        print("AP confirms client acknowledgment")
        
        self.pause_for_user("Press Enter to view handshake completion summary...")
        
        # Handshake completion summary
        print("HANDSHAKE COMPLETION SUMMARY")
        print("=" * 70)
        print("4-Way Handshake completed successfully!")
        print("All authentication and key exchange stages passed")
        print()
        print("INSTALLED KEYS:")
        print(f"  PMK: {self.hexlify(self.pmk[:16])}... (Pairwise Master Key)")
        print(f"  PTK: {self.hexlify(self.ptk[:16])}... (Pairwise Transient Key)")
        print(f"  GTK: {self.hexlify(self.gtk[:16])}... (Group Temporal Key)")
        print()
        print("SECURITY STATUS:")
        print("  - Port Status: AUTHORIZED")
        print("  - Encryption: ENABLED")
        print("  - Unicast Traffic: Protected by PTK")
        print("  - Broadcast/Multicast Traffic: Protected by GTK")
        print("  - Secure Communication: ESTABLISHED")
        print("=" * 70)
        
        return True

def display_header():
    """Display university and student information header"""
    print("=" * 70)
    print("Kapasa Makasa University")
    print("Department of Information Communication Technology")
    print("CYS 331")
    print()
    print("=" * 70)
    print("STUDENT: Gabriel Kapambwe")
    print("SIN#: 20230192 ")
    print("Program: CyberSecurity")
    print("=" * 70)
    print("Task: 4-Way Handshake Simulator")
    print("=" * 70)
    print()

def get_user_input():
    """
    Collect and validate user input for network parameters
    
    Returns:
        tuple: (ssid, password, sanitized_client_mac, original_client_mac, 
                sanitized_ap_mac, original_ap_mac) or None if validation fails
    """
    simulator = WPA2HandshakeSimulator()
    
    print("NETWORK CONFIGURATION INPUT")
    print("-" * 30)
    print("Please enter the following network details for handshake simulation:")
    print()
    
    # Get network SSID
    while True:
        ssid = input("Enter Network SSID: ").strip()
        if ssid:
            break
        print("ERROR: SSID cannot be empty. Please enter a valid SSID.")
    
    # Get network password
    while True:
        password = input("Enter Wi-Fi Password: ").strip()
        if len(password) >= 8:
            break
        print("ERROR: Password must be at least 8 characters long.")
    
    # Get and validate client MAC address
    while True:
        client_mac_input = input("Enter Client MAC Address: ").strip()
        sanitized_client_mac = simulator.sanitize_mac_address(client_mac_input)
        
        if sanitized_client_mac:
            print(f"Client MAC sanitized: {client_mac_input} -> {sanitized_client_mac}")
            break
        else:
            print("ERROR: Invalid MAC address format.")
            print("Accepted formats: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXXXXXXXXXX")
            print("Example: 00:11:22:33:44:55")
    
    # Get and validate AP MAC address
    while True:
        ap_mac_input = input("Enter AP MAC Address: ").strip()
        sanitized_ap_mac = simulator.sanitize_mac_address(ap_mac_input)
        
        if sanitized_ap_mac:
            print(f"AP MAC sanitized: {ap_mac_input} -> {sanitized_ap_mac}")
            break
        else:
            print("ERROR: Invalid MAC address format.")
            print("Accepted formats: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXXXXXXXXXX")
            print("Example: 66:77:88:99:AA:BB")
    
    # Ensure MAC addresses are different
    if sanitized_client_mac == sanitized_ap_mac:
        print("ERROR: Client and AP MAC addresses must be different.")
        return None
    
    return (ssid, password, sanitized_client_mac, client_mac_input, 
            sanitized_ap_mac, ap_mac_input)

def main():
    """
    Main function to orchestrate the handshake simulation
    
    Controls the overall flow of the program including:
    - Display of header information
    - User input collection and validation
    - Handshake simulation execution
    - Final status reporting
    """
    # Display university and course information
    display_header()
    
    # Collect user input with validation
    input_data = get_user_input()
    if not input_data:
        print("Simulation aborted due to invalid input.")
        return
    
    ssid, password, client_mac, client_mac_orig, ap_mac, ap_mac_orig = input_data
    
    print("\nInput validation completed successfully.")
    input("\nPress Enter to start the 4-way handshake simulation...")
    print()
    
    # Initialize simulator and run handshake
    simulator = WPA2HandshakeSimulator()
    success = simulator.simulate_handshake(
        ssid, password, client_mac, client_mac_orig, ap_mac, ap_mac_orig
    )
    
    # Display final simulation results
    print("\nSIMULATION RESULTS")
    print("=" * 20)
    if success:
        print("STATUS: HANDSHAKE SUCCESSFUL")
        print("RESULT: Client successfully authenticated and connected to AP")
        print("SECURITY: Secure communication channel established")
    else:
        print("STATUS: HANDSHAKE FAILED")
        print("RESULT: Authentication failed - connection denied")
        print("CAUSE: Key derivation error or message integrity failure")
    
    print("\nSimulation completed.")
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()
