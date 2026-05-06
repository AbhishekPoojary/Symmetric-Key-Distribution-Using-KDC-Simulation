"""
=============================================================================
  Needham-Schroeder Protocol: Replay Attack Demonstration
=============================================================================

This script demonstrates:
  Phase 1 — Normal Needham-Schroeder protocol execution (all steps)
  Phase 2 — Replay attack SUCCEEDING (without timestamp validation)
  Phase 3 — Replay attack BLOCKED (with timestamp validation)

Run:  python replay_attack_demo.py
=============================================================================
"""

import random
import time
import des
import library


# ──────────────────────────── Helpers ────────────────────────────

def random10bit():
    """Generate a random 10-bit binary string."""
    return "".join(str(random.randint(0, 1)) for _ in range(10))


def separator(char="=", length=70):
    print(char * length)


def header(text):
    print()
    separator()
    print(f"  {text}")
    separator()


def step_msg(num, text):
    print(f"\n  [Step {num}] {text}")


def info(text):
    print(f"    -> {text}")


def ok(text):
    print(f"    [OK]  {text}")


def fail(text):
    print(f"    [!!]  {text}")


def pause(seconds=1):
    time.sleep(seconds)


# ──────────────────────────── Phase 1 ────────────────────────────

def phase1_normal_protocol():
    header("PHASE 1: Normal Needham-Schroeder Protocol")

    # ── Setup ──
    Ka = random10bit()          # Alice's master key shared with KDC
    Kb = random10bit()          # Bob's master key shared with KDC
    IDa = "00000001"            # Alice's identifier
    IDb = "00000002"            # Bob's identifier
    IDa_bin = bin(int(IDa))[2:].zfill(8)
    IDb_bin = bin(int(IDb))[2:].zfill(8)

    print(f"\n  {'  TEST DATA  ':=^66}")
    print(f"    Alice's Master Key  Ka = {Ka}  (decimal {int(Ka, 2)})")
    print(f"    Bob's Master Key    Kb = {Kb}  (decimal {int(Kb, 2)})")
    print(f"    Alice's ID         IDa = {IDa}")
    print(f"    Bob's ID           IDb = {IDb}")
    print(f"  {'':=<66}\n")
    pause()

    # ── Step 1: Alice -> KDC ──
    N1 = random10bit()
    step_msg(1, "Alice -> KDC :  IDa || IDb || N1")
    info(f"Nonce N1 = {N1}")
    info(f"Plaintext sent: {IDa}{IDb}{N1}")
    pause()

    # ── Step 2: KDC -> Alice ──
    Ks = random10bit()  # session key
    step_msg(2, "KDC -> Alice :  E(Ka, [Ks || IDb || E(Kb, [Ks || IDa])])")
    info(f"Session Key generated  Ks = {Ks}  (decimal {int(Ks, 2)})")

    # Inner envelope for Bob (encrypted with Kb)
    inner_plain = Ks + IDa_bin
    inner_cipher = library.encrypt(inner_plain, Kb)
    info(f"Inner envelope plaintext : {inner_plain}")
    info(f"Inner envelope ciphertext: {inner_cipher[:40]}...")

    # Outer envelope for Alice (encrypted with Ka)
    outer_plain = Ks + IDb_bin + inner_cipher
    outer_cipher = library.encrypt(outer_plain, Ka)
    info(f"Outer envelope ciphertext: {outer_cipher[:40]}...")
    pause()

    # ── Step 3: Alice decrypts, forwards inner envelope to Bob ──
    step_msg(3, "Alice decrypts outer envelope, forwards inner to Bob")
    outer_dec = library.decrypt(outer_cipher, Ka)
    recovered_Ks = outer_dec[:10]
    recovered_IDb = outer_dec[10:18]
    recovered_inner = outer_dec[18:]
    ok(f"Alice recovers Ks = {recovered_Ks}")
    ok(f"Alice identifies Bob (IDb = {recovered_IDb})")
    info("Alice sends inner envelope to Bob")
    pause()

    # ── Step 4: Bob decrypts, sends challenge nonce ──
    step_msg(4, "Bob decrypts inner envelope, sends challenge nonce N2")
    inner_dec = library.decrypt(inner_cipher, Kb)
    bob_Ks = inner_dec[:10]
    bob_IDa = inner_dec[10:18]
    ok(f"Bob recovers Ks = {bob_Ks}")
    ok(f"Bob identifies Alice (IDa = {bob_IDa})")

    N2 = random10bit()
    enc_N2 = library.encrypt(N2, Ks)
    info(f"Bob's challenge nonce N2 = {N2}")
    info(f"Bob sends E(Ks, N2) to Alice")
    pause()

    # ── Step 5: Alice computes f(N2) = N2 - 1 ──
    step_msg(5, "Alice decrypts N2, computes f(N2) = N2 - 1, sends back")
    dec_N2 = library.decrypt(enc_N2, Ks)
    info(f"Alice decrypts -> N2 = {dec_N2}")
    f_N2 = bin(int(N2, 2) - 1)[2:].zfill(10)
    enc_f_N2 = library.encrypt(f_N2, Ks)
    info(f"f(N2) = {N2} - 1 = {f_N2}")
    info(f"Alice sends E(Ks, f(N2)) to Bob")
    pause()

    # ── Step 6: Bob verifies ──
    step_msg(6, "Bob verifies f(N2)")
    dec_f_N2 = library.decrypt(enc_f_N2, Ks)
    expected = int(N2, 2) - 1
    received = int(dec_f_N2, 2)
    if received == expected:
        ok(f"Verification PASSED  (received {received} == expected {expected})")
        ok("Secure channel established!  Alice and Bob can now chat.")
    else:
        fail(f"Verification FAILED  (received {received} != expected {expected})")
    pause()

    # Return values needed for replay demo
    return Ka, Kb, Ks, IDa, IDb, inner_cipher


# ──────────────────────────── Phase 2 ────────────────────────────

def phase2_replay_attack(Kb, Ks, inner_cipher):
    header("PHASE 2: Replay Attack (WITHOUT Timestamps)")

    print("""
    SCENARIO:
    An attacker (Darth) previously eavesdropped on the communication
    and captured the inner envelope E(Kb, [Ks || IDa]) from Step 3.

    Later, the session key Ks is compromised (e.g., through brute
    force on the simplified DES).

    Darth now replays the old inner envelope to Bob, pretending to be
    Alice. Since there is NO timestamp, Bob has no way to tell that
    this message is old and replayed.
    """)
    pause(2)

    step_msg("A", "Darth replays the captured inner envelope to Bob")
    info(f"Replayed ciphertext: {inner_cipher[:40]}...")
    pause()

    step_msg("B", "Bob decrypts the replayed envelope (no timestamp to check)")
    inner_dec = library.decrypt(inner_cipher, Kb)
    bob_Ks = inner_dec[:10]
    bob_IDa = inner_dec[10:18]
    info(f"Bob decrypts -> Ks = {bob_Ks}, IDa = {bob_IDa}")
    fail("Bob ACCEPTS the replayed message — he thinks Alice is connecting!")
    pause()

    step_msg("C", "Darth uses the compromised Ks to respond to Bob's challenge")
    N2 = random10bit()
    info(f"Bob sends challenge N2 = {N2}")
    f_N2 = bin(int(N2, 2) - 1)[2:].zfill(10)
    enc_f_N2 = library.encrypt(f_N2, Ks)
    info(f"Darth computes f(N2) = {f_N2} using compromised Ks")
    pause()

    step_msg("D", "Bob verifies — attack succeeds!")
    dec_f_N2 = library.decrypt(enc_f_N2, Ks)
    if int(dec_f_N2, 2) == int(N2, 2) - 1:
        fail("Bob VERIFIES Darth as Alice — REPLAY ATTACK SUCCESSFUL!")
        fail("Darth now has a 'secure' channel with Bob, impersonating Alice.")
    pause()


# ──────────────────────────── Phase 3 ────────────────────────────

def phase3_timestamp_prevention(Ka, Kb):
    header("PHASE 3: Replay Attack PREVENTED (WITH Timestamps)")

    print("""
    SOLUTION:
    The KDC now includes a real timestamp T in the envelope:
        E(Kb, [Ks || IDa || T])

    Bob validates that T is recent (within a 30-second window).
    If the timestamp is expired, Bob REJECTS the message.
    """)
    pause(2)

    VALIDITY_WINDOW = 30  # seconds

    IDa = "00000001"
    IDb = "00000002"
    IDa_bin = bin(int(IDa))[2:].zfill(8)

    # ── Normal exchange with timestamp ──
    step_msg(1, "KDC creates envelope WITH timestamp")
    Ks = random10bit()
    current_epoch = int(time.time())
    T = bin(current_epoch % 1024)[2:].zfill(10)
    inner_plain = Ks + IDa_bin + T
    inner_cipher = library.encrypt(inner_plain, Kb)
    info(f"Session Key Ks = {Ks}")
    info(f"Timestamp T    = {T}  (epoch % 1024 = {current_epoch % 1024})")
    info(f"Inner envelope: E(Kb, [Ks || IDa || T])")
    pause()

    step_msg(2, "Bob receives fresh envelope - validates timestamp")
    inner_dec = library.decrypt(inner_cipher, Kb)
    dec_Ks = inner_dec[:10]
    dec_IDa = inner_dec[10:18]
    dec_T = inner_dec[18:]
    dec_T_val = int(dec_T, 2)
    current_val = int(time.time()) % 1024
    diff = min(abs(current_val - dec_T_val), 1024 - abs(current_val - dec_T_val))
    info(f"Decrypted timestamp = {dec_T} (value = {dec_T_val})")
    info(f"Current time mod 1024 = {current_val}")
    info(f"Time difference     = {diff} seconds")
    if diff < VALIDITY_WINDOW:
        ok(f"Timestamp is FRESH ({diff}s < {VALIDITY_WINDOW}s window) - ACCEPTED")
    pause()

    # ── Simulated replay attack ──
    step_msg(3, "Darth captures the envelope and waits...")
    old_epoch = current_epoch - 120  # 2 minutes ago
    fake_old_T = bin(old_epoch % 1024)[2:].zfill(10)
    old_inner_plain = Ks + IDa_bin + fake_old_T
    old_inner_cipher = library.encrypt(old_inner_plain, Kb)
    info(f"Darth captured envelope with timestamp = {fake_old_T} (value = {old_epoch % 1024})")
    info(f"Darth waits... (simulating 120 seconds passing)")
    pause()

    step_msg(4, "Darth replays the old envelope to Bob")
    info(f"Replayed ciphertext: {old_inner_cipher[:40]}...")
    pause()

    step_msg(5, "Bob decrypts and validates the timestamp")
    old_dec = library.decrypt(old_inner_cipher, Kb)
    old_T = old_dec[18:]
    old_T_val = int(old_T, 2)
    current_val = int(time.time()) % 1024
    diff = min(abs(current_val - old_T_val), 1024 - abs(current_val - old_T_val))
    info(f"Decrypted timestamp = {old_T} (value = {old_T_val})")
    info(f"Current time mod 1024 = {current_val}")
    info(f"Time difference     = {diff} seconds")

    if diff >= VALIDITY_WINDOW:
        ok(f"Timestamp EXPIRED ({diff}s >= {VALIDITY_WINDOW}s window)")
        ok("Bob REJECTS the replayed message!")
        ok("REPLAY ATTACK PREVENTED!")
    else:
        fail("Timestamp still valid - attack not prevented.")
    pause()


# ──────────────────────────── Main ────────────────────────────

def wait_for_user(prompt):
    """Prompt user to continue; auto-continue if non-interactive."""
    try:
        input(prompt)
    except EOFError:
        print()


def main():
    print("""
    ==================================================================
     NEEDHAM-SCHROEDER PROTOCOL: REPLAY ATTACK DEMONSTRATION
    ==================================================================
     This demo simulates the complete NS protocol and shows:

       Phase 1 - Normal protocol execution (6 steps)
       Phase 2 - Replay attack WITHOUT timestamps (succeeds)
       Phase 3 - Replay attack WITH timestamps    (blocked)

     Encryption: Simplified DES (S-DES) with 10-bit keys
    ==================================================================
    """)

    wait_for_user("  Press ENTER to begin...\n")

    # Phase 1: Normal protocol
    Ka, Kb, Ks, IDa, IDb, inner_cipher = phase1_normal_protocol()

    print("\n")
    wait_for_user("  Press ENTER for Phase 2 (Replay Attack)...\n")

    # Phase 2: Replay attack without timestamps
    phase2_replay_attack(Kb, Ks, inner_cipher)

    print("\n")
    wait_for_user("  Press ENTER for Phase 3 (Timestamp Prevention)...\n")

    # Phase 3: Timestamp prevention
    phase3_timestamp_prevention(Ka, Kb)

    # Summary
    header("SUMMARY")
    print("""
    1. The Needham-Schroeder protocol securely distributes a session
       key between Alice and Bob through a trusted KDC.

    2. WITHOUT timestamps, an attacker who captures old messages and
       compromises a session key can REPLAY those messages to
       impersonate a legitimate user.

    3. WITH timestamps, Bob validates that the envelope is recent.
       Old/replayed messages are REJECTED because their timestamps
       fall outside the validity window.

    4. This implementation uses a {WINDOW}-second validity window.
       Messages older than this are automatically rejected.
    """.format(WINDOW=30))
    separator()
    print("  Demo complete.\n")


if __name__ == "__main__":
    main()
