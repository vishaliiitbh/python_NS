import tkinter as tk
from tkinter import ttk
import random
import time
from threading import Thread
import hashlib
from datetime import datetime


class Entity:
    def __init__(self, name, pos):
        self.name = name
        self.pos = pos
        self.keys = {}
        self.nonce = None
        self.session_key = None
        self.intercepted_nonce = None  # For attacker to store intercepted nonces


class Packet:
    def __init__(self, source, dest, data, step):
        self.source = source
        self.dest = dest
        self.data = data
        self.step = step
        self.x = source.pos[0]
        self.y = source.pos[1]


class NeedhamSchroederProtocol:
    def __init__(self, root):
        self.root = root
        self.root.title("Needham-Schroeder Protocol Simulation")

        # Setup main container
        self.main_frame = ttk.Frame(root, padding="10")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Canvas for visualization
        self.canvas = tk.Canvas(self.main_frame, width=700, height=500, bg='white')
        self.canvas.grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)

        # Controls
        self.controls_frame = ttk.Frame(self.main_frame)
        self.controls_frame.grid(row=1, column=0, columnspan=2, pady=10)

        self.start_btn = ttk.Button(self.controls_frame, text="Start Protocol",
                                  command=self.start_protocol)
        self.start_btn.grid(row=0, column=0, padx=5)

        # Add attack button
        self.attack_btn = ttk.Button(self.controls_frame, text="Simulate Attack",
                                   command=self.start_attack)
        self.attack_btn.grid(row=0, column=1, padx=5)

        # Log area
        self.log_frame = ttk.Frame(self.main_frame)
        self.log_frame.grid(row=2, column=0, columnspan=2, pady=10)

        self.log_text = tk.Text(self.log_frame, height=15, width=60)
        self.log_text.grid(row=0, column=0)

        scrollbar = ttk.Scrollbar(self.log_frame, orient="vertical",
                                command=self.log_text.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scrollbar.set)

        # Calculation area for mathematical steps
        self.calc_frame = ttk.Frame(self.main_frame, width=200)
        self.calc_frame.grid(row=0, column=1, padx=5, sticky=tk.N)

        self.calc_text = tk.Text(self.calc_frame, height=30, width=30)
        self.calc_text.grid(row=0, column=0, padx=5)

        # Initialize protocol entities
        self.setup_entities()
        self.running = False

    def setup_entities(self):
        # Create entities with their positions
        self.alice = Entity("Alice", (100, 250))
        self.bob = Entity("Bob", (600, 250))
        self.server = Entity("Server", (350, 100))
        self.attacker = Entity("Attacker", (350, 400))  # Add attacker entity

        # Setup long-term keys
        self.alice.keys['KAS'] = self.generate_key("KAS")  # Alice-Server key
        self.bob.keys['KBS'] = self.generate_key("KBS")  # Bob-Server key
        self.server.keys['KAS'] = self.alice.keys['KAS']  # Server knows both keys
        self.server.keys['KBS'] = self.bob.keys['KBS']
        self.attacker.keys['KBS'] = self.generate_key("KCS")  # Attacker's key

        # Draw entities on canvas
        self.draw_entity(self.alice, 'lightblue')
        self.draw_entity(self.bob, 'lightgreen')
        self.draw_entity(self.server, 'lightyellow')
        self.draw_entity(self.attacker, 'pink')

    def simulate_attack(self):
        try:
            # Step 1: A → C: {A, Na}pub(C)
            self.log_message("\nStarting Man-in-the-Middle Attack Simulation")
            self.alice.nonce = self.generate_nonce()
            step1_msg = self.encrypt(f"{self.alice.name}, {self.alice.nonce}",
                                   self.attacker.keys['KBS'])
            self.show_calculation(
                f"Step 1 (Attack):\nA → C:\n"
                f"Message: Enc_pubC(A, Na)\n"
                f"Where:\n"
                f"  Na = {self.alice.nonce}\n"
                f"Alice initiates protocol with Attacker C"
            )
            packet = Packet(self.alice, self.attacker, step1_msg, "A1")
            self.animate_packet(packet)
            time.sleep(1)

            # Step 2: C(A) → B: {A, Na}pub(B)
            self.attacker.intercepted_nonce = self.alice.nonce
            step2_msg = self.encrypt(f"{self.alice.name}, {self.attacker.intercepted_nonce}",
                                   self.bob.keys['KBS'])
            self.show_calculation(
                f"Step 2 (Attack):\nC(A) → B:\n"
                f"Message: Enc_pubB(A, Na)\n"
                f"Where:\n"
                f"  Na = {self.attacker.intercepted_nonce}\n"
                f"Attacker forwards Alice's nonce to Bob, impersonating Alice"
            )
            packet = Packet(self.attacker, self.bob, step2_msg, "A2")
            self.animate_packet(packet)
            time.sleep(1)

            # Step 3: B → C(A): {Na, Nb}pub(A)
            self.bob.nonce = self.generate_nonce()
            step3_msg = self.encrypt(
                f"{self.attacker.intercepted_nonce}, {self.bob.nonce}",
                self.alice.keys['KAS']
            )
            self.show_calculation(
                f"Step 3 (Attack):\nB → C(A):\n"
                f"Message: Enc_pubA(Na, Nb)\n"
                f"Where:\n"
                f"  Nb = {self.bob.nonce}\n"
                f"Bob responds to who he thinks is Alice"
            )
            packet = Packet(self.bob, self.attacker, step3_msg, "A3")
            self.animate_packet(packet)
            time.sleep(1)

            # Step 4: C → A: {Na, Nb}pub(A)
            step4_msg = step3_msg  # Attacker forwards the message unchanged
            self.show_calculation(
                f"Step 4 (Attack):\nC → A:\n"
                f"Message: Enc_pubA(Na, Nb)\n"
                f"Attacker forwards Bob's response to Alice"
            )
            packet = Packet(self.attacker, self.alice, step4_msg, "A4")
            self.animate_packet(packet)
            time.sleep(1)

            # Step 5: A → C: {Nb}pub(C)
            step5_msg = self.encrypt(str(self.bob.nonce), self.attacker.keys['KBS'])
            self.show_calculation(
                f"Step 5 (Attack):\nA → C:\n"
                f"Message: Enc_pubC(Nb)\n"
                f"Alice responds to Attacker with Bob's nonce"
            )
            packet = Packet(self.alice, self.attacker, step5_msg, "A5")
            self.animate_packet(packet)
            time.sleep(1)

            # Step 6: C(A) → B: {Nb}pub(B)
            step6_msg = self.encrypt(str(self.bob.nonce), self.bob.keys['KBS'])
            self.show_calculation(
                f"Step 6 (Attack):\nC(A) → B:\n"
                f"Message: Enc_pubB(Nb)\n"
                f"Attacker completes protocol with Bob"
            )
            packet = Packet(self.attacker, self.bob, step6_msg, "A6")
            self.animate_packet(packet)
            time.sleep(1)

            # Attack completion
            self.log_message("\nMan-in-the-Middle Attack Completed!")
            self.log_message("Attacker has successfully intercepted communication")
            self.show_calculation(
                "Attack Summary:\n\n"
                "1. Attacker intercepted initial communication from Alice\n"
                "2. Impersonated Alice to Bob\n"
                "3. Intercepted Bob's response\n"
                "4. Established separate sessions with both Alice and Bob\n"
                f"Intercepted Nonces:\n"
                f"  Na = {self.alice.nonce}\n"
                f"  Nb = {self.bob.nonce}"
            )

        except Exception as e:
            self.log_message(f"Attack simulation error: {str(e)}")
        finally:
            self.running = False

    def start_attack(self):
        if not self.running:
            self.running = True
            self.log_text.delete(1.0, tk.END)
            self.calc_text.delete(1.0, tk.END)
            Thread(target=self.simulate_attack).start()

    # [Keep all other existing methods from the original code...]
    def draw_entity(self, entity, color):
        x, y = entity.pos
        self.canvas.create_oval(x - 25, y - 25, x + 25, y + 25, fill=color,
                              tags=entity.name.lower())
        self.canvas.create_text(x, y - 40, text=entity.name,
                              tags=f"{entity.name.lower()}_label")

    def generate_key(self, seed):
        return hashlib.sha256(f"{seed}{time.time()}".encode()).hexdigest()[:16]

    def generate_nonce(self):
        return random.randint(10000, 99999)

    def encrypt(self, message, key):
        encrypted = hashlib.sha256(f"{message}{key}".encode()).hexdigest()[:12]
        return f"Enc({encrypted})"

    def decrypt(self, message, key):
        return message.replace("Enc(", "").replace(")", "")

    def log_message(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.log_text.see(tk.END)

    def show_calculation(self, message):
        self.calc_text.delete(1.0, tk.END)
        self.calc_text.insert(tk.END, message)

    def animate_packet(self, packet):
        dx = (packet.dest.pos[0] - packet.x) / 50
        dy = (packet.dest.pos[1] - packet.y) / 50

        packet_id = self.canvas.create_oval(packet.x - 5, packet.y - 5,
                                          packet.x + 5, packet.y + 5,
                                          fill='red')
        message_id = self.canvas.create_text(packet.x, packet.y - 15,
                                           text=f"Step {packet.step}")

        for _ in range(50):
            if not self.running:
                self.canvas.delete(packet_id, message_id)
                return
            packet.x += dx
            packet.y += dy
            self.canvas.coords(packet_id, packet.x - 5, packet.y - 5,
                             packet.x + 5, packet.y + 5)
            self.canvas.coords(message_id, packet.x, packet.y - 15)
            self.canvas.update()
            time.sleep(0.09)

        self.canvas.delete(packet_id, message_id)

    def start_protocol(self):
        if not self.running:
            self.running = True
            self.log_text.delete(1.0, tk.END)
            self.calc_text.delete(1.0, tk.END)
            Thread(target=self.run_protocol).start()

    def run_protocol(self):
        try:
            # Step 1: A → S: A, B, Ni
            self.log_message("Step 1: Alice initiates communication with Server")
            self.alice.nonce = self.generate_nonce()
            step1_msg = f"{self.alice.name}, {self.bob.name}, {self.alice.nonce}"
            self.show_calculation(
                f"Step 1:\nAlice → Server:\nMessage: (A, B, Ni)\nWhere:\n  A = Alice\n  B = Bob\n  Ni = Nonce generated by Alice = {self.alice.nonce}")
            packet = Packet(self.alice, self.server, step1_msg, 1)
            self.animate_packet(packet)
            time.sleep(1)

            # Step 2: S → A: {Ni, KAB, B, {KAB, A}KBS}KAS
            self.log_message("Step 2: Server processes request and responds")
            session_key = self.generate_key("KAB")
            ticket = self.encrypt(f"{session_key}, {self.alice.name}", self.bob.keys['KBS'])
            encrypted_msg = self.encrypt(
                f"{self.alice.nonce}, {session_key}, {self.bob.name}, {ticket}",
                self.alice.keys['KAS']
            )
            self.show_calculation(
                f"Step 2:\nServer → Alice:\nMessage: Enc_KAS(Ni, K_AB, B, Enc_KBS(K_AB, A))\nWhere:\n"
                f"  K_AB = Session key = {session_key}\n"
                f"  Enc_KBS(K_AB, A) = Ticket for Bob = {ticket}\n"
                f"  Enc_KAS(...) = Encrypted message to Alice with shared key K_AS"
            )
            packet = Packet(self.server, self.alice, encrypted_msg, 2)
            self.animate_packet(packet)
            time.sleep(1)

            # Step 3: A → B: {KAB, A}KBS
            self.log_message("Step 3: Alice forwards ticket to Bob")
            self.show_calculation(f"Step 3:\nAlice → Bob:\nMessage: Enc_KBS(K_AB, A)\nWhere:\n  Ticket = {ticket}")
            packet = Packet(self.alice, self.bob, ticket, 3)
            self.animate_packet(packet)
            time.sleep(1)

            # Step 4: B → A: {Nj}KAB
            self.log_message("Step 4: Bob sends challenge to Alice")
            self.bob.nonce = self.generate_nonce()
            encrypted_nonce = self.encrypt(str(self.bob.nonce), session_key)
            self.log_message(f"Bob generates nonce Nj: {self.bob.nonce}")
            self.show_calculation(f"Step 4:\nBob → Alice:\nMessage: Enc_KAB(Nj)\nWhere:\n  Nj = {self.bob.nonce}")
            packet = Packet(self.bob, self.alice, encrypted_nonce, 4)
            self.animate_packet(packet)
            time.sleep(1)

            # Step 5: A → B: {Nj-1}KAB
            self.log_message("Step 5: Alice responds to challenge")
            modified_nonce = self.bob.nonce - 1
            encrypted_response = self.encrypt(str(modified_nonce), session_key)
            self.show_calculation(f"Step 5:\nAlice → Bob:\nMessage: Enc_KAB(Nj-1)\nWhere:\n  Nj-1 = {modified_nonce}")
            packet = Packet(self.alice, self.bob, encrypted_response, 5)
            self.animate_packet(packet)
            time.sleep(1)

            # Step 6: Secure communication established
            self.log_message("\nProtocol completed successfully!")
            self.log_message(f"Secure session established with key: {session_key}")
            self.show_calculation(f"Protocol Complete.\nSession Key: {session_key}")

        except Exception as e:
            self.log_message(f"Error occurred: {str(e)}")
        finally:
            self.running = False


def main():
    root = tk.Tk()
    app = NeedhamSchroederProtocol(root)
    root.mainloop()


if __name__ == "__main__":
    main()