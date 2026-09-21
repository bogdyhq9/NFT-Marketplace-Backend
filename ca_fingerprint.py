import numpy as np
import hashlib
import base64
import hmac
import secrets
from typing import Dict, Tuple, List, Union, Optional
from ca_hash_function import CAHashFunction, BipermutativeCA
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from  db_models import Fingerprint

class CAFingerprint:
    """
    SHA-free fingerprinting using a sponge-style construction on top of
    bipermutative cellular automata.
 
    Data is absorbed directly into the CA state (no pre-hashing), the CA
    permutation is applied between blocks, and the fingerprint is squeezed
    out of the state. The only nonlinear/mixing primitive is the CA.
 
    State layout (ca_width bits):
        [ rate bits | capacity bits ]
    Input is XORed only into the rate part; the capacity part is never
    touched directly, and it is what the security level rests on
    (generic collision bound ~ 2^(capacity/2)).
    """
 
    _RULE_SEQUENCES = (
        ['r3', 'r1', 'r4', 'r2', 'r2', 'r4', 'r3', 'r1', 'r4', 'r3', 'r1', 'r2'],
        ['r2', 'r4', 'r1', 'r3', 'r4', 'r1', 'r2', 'r3', 'r1', 'r4', 'r3', 'r2'],
        ['r4', 'r2', 'r3', 'r1', 'r3', 'r2', 'r4', 'r1', 'r2', 'r3', 'r1', 'r4'],
    )
 
    def __init__(self, ca_width: int = 256, output_size: int = 32,
                 rounds: int = 16, rate: int = 128):
        """
        Args:
            ca_width:    CA array width in bits (must be divisible by 32).
            output_size: fingerprint size in bytes.
            rounds:      CA rounds per permutation call (applied once per absorbed block
                         and once per extra squeezed block).
            rate:        bits absorbed per block (multiple of 8, < ca_width).
                         capacity = ca_width - rate. For ~128-bit collision
                         resistance use e.g. ca_width=512, rate=256.
        """
        assert ca_width % 32 == 0, "ca_width must be divisible by 32"
        assert rate % 8 == 0 and 0 < rate < ca_width, "rate must be a multiple of 8 and < ca_width"
 
        self.ca_width = ca_width
        self.output_size = output_size
        self.rounds = rounds
        self.rate = rate
 
        self.ca_hash = CAHashFunction(width=ca_width, output_size=output_size)
 
        self.transform_rules = {
            'f1': 2573874129,
            'f2': 3798145627,
            'f3': 1654278349,
        }
        self.transform_cas = {
            name: BipermutativeCA(rule, ca_width)
            for name, rule in self.transform_rules.items()
        }
 
        # Public round constants: CAs are translation-invariant on a ring, so
        # constants are needed to break symmetry between rounds.
        self.round_constants = self._make_round_constants(ca_width, rounds)
 
    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _make_round_constants(width: int, count: int):
        """Nothing-up-my-sleeve constants from a fixed-seed xorshift64 stream."""
        mask = (1 << 64) - 1
        x = 0x9E3779B97F4A7C15
        constants = []
        for _ in range(count):
            bits = []
            while len(bits) < width:
                x ^= (x << 13) & mask
                x ^= x >> 7
                x ^= (x << 17) & mask
                bits.extend((x >> k) & 1 for k in range(63, -1, -1))
            constants.append(np.array(bits[:width], dtype=np.int8))
        return constants
 
    def _pad_bits(self, msg: bytes) -> np.ndarray:
        """pad10*1 padding, returns bit array whose length is a multiple of rate."""
        bits = np.unpackbits(np.frombuffer(msg, dtype=np.uint8)).astype(np.int8)
        pad_zeros = (-(len(bits) + 2)) % self.rate
        return np.concatenate([
            bits,
            np.array([1], dtype=np.int8),
            np.zeros(pad_zeros, dtype=np.int8),
            np.array([1], dtype=np.int8),
        ])
 
    def _apply_transformations(self, state: np.ndarray) -> np.ndarray:
        """Fingerprint-specific CA transformations with 4-way quarter mixing."""
        q = self.ca_width // 4
        for rule_name in ['f1', 'f2', 'f3', 'f1', 'f3', 'f2']:
            ca = self.transform_cas[rule_name]
            ca.initialize_state(state)
            state = np.array(ca.step(), dtype=np.int8, copy=True)  # copy: don't alias CA internals
 
            a, b, c, d = state[:q].copy(), state[q:2*q].copy(), state[2*q:3*q].copy(), state[3*q:].copy()
            state[:q] = a ^ b
            state[q:2*q] = b ^ c
            state[2*q:3*q] = c ^ d
            state[3*q:] = d ^ a
        return state
 
    def _permute(self, state: np.ndarray) -> np.ndarray:
        """The CA-based permutation (round function) used by absorb and squeeze."""
        for i in range(self.rounds):
            state = state ^ self.round_constants[i]
 
            if i % 5 == 0:
                state = self._apply_transformations(state)
 
            for rule_name in self._RULE_SEQUENCES[i % 3]:
                ca = self.ca_hash.ca_instances[rule_name]
                ca.initialize_state(state)
                state = np.array(ca.step(), dtype=np.int8, copy=True)
 
            if i % 7 == 6:
                for j in range(0, self.ca_width, 32):
                    state[j:j+32] = state[j:j+32][::-1]
        return state
 
    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def generate_fingerprint(self, data: Union[str, bytes], salt: bytes = b"") -> bytes:
        """
        Args:
            data: input (str is UTF-8 encoded). Normalise (lowercase, strip spaces)
                  before calling if you want that behaviour.
            salt: optional *random, stored* per-identity salt. Unlike the old
                  data-derived salt, this actually adds entropy/uniqueness.
        """
        if isinstance(data, str):
            data = data.encode('utf-8')
        # Length-prefixed salt so (salt, data) pairs can't be confused
        msg = len(salt).to_bytes(2, 'big') + salt + data
 
        state = np.zeros(self.ca_width, dtype=np.int8)
 
        # Absorb
        for block in self._pad_bits(msg).reshape(-1, self.rate):
            state[:self.rate] ^= block
            state = self._permute(state)
 
        # Squeeze
        n_bits = self.output_size * 8
        out = []
        got = 0
        while True:
            out.append(state[:self.rate].copy())
            got += self.rate
            if got >= n_bits:
                break
            state = self._permute(state)
 
        bits = np.concatenate(out)[:n_bits].astype(np.uint8)
        return np.packbits(bits).tobytes()
 
    def encode_fingerprint(self, fingerprint: bytes) -> str:
        return base64.b64encode(fingerprint).decode('utf-8')
 
    def verify_fingerprint(self, data: Union[str, bytes], stored_fingerprint: str,
                           salt: bytes = b"") -> bool:
        generated = self.generate_fingerprint(data, salt)
        try:
            stored = base64.b64decode(stored_fingerprint)
        except Exception:
            return False
        return hmac.compare_digest(generated, stored)

class UserVerificationSystem:
    """
    A simplified system for managing user identity verification using CA fingerprinting.
    """
    
    def __init__(self, ca_width: int = 256, fingerprint_size: int = 32, iterations: int = 50, db_url: str = 'sqlite:///fingerprints.db'):
        """
        Initialize the verification system.
        
        Args:
            ca_width: Width of the CA array
            fingerprint_size: Size of fingerprints in bytes
            iterations: Number of CA iterations to perform
            db_url: Database connection URL
        """
        self.fingerprinter = CAFingerprint(
            ca_width=ca_width,
            output_size=fingerprint_size,
            iterations=iterations
        )
        self.user_db = {}  # Simulated database for demonstration
        
        # Database setup
        self.engine = create_engine(db_url, echo=False)
        self.Session = sessionmaker(bind=self.engine)
        
    def format_user_data(self, first_name: str, last_name: str, passport: str, series: str) -> str:
        """
        Format user data into a consistent string for fingerprinting
        
        Args:
            first_name: User's first name
            last_name: User's last name
            passport: Passport number
            series: Passport series
        
        Returns:
            Formatted string for fingerprinting
        """
        # Convert to lowercase and remove spaces for consistency
        formatted_data = f"{first_name.lower().strip()}{last_name.lower().strip()}{passport.lower().strip()}{series.lower().strip()}"
        
        return formatted_data

    def verify_fingerprint_in_db(self, formatted_data: str) -> bool:
        """
        Generate fingerprint from formatted data and check if it exists in database
        
        Args:
            formatted_data: The formatted user data string
        
        Returns:
            True if fingerprint exists in database, False otherwise
        """
        session = self.Session()
        
        try:
            # Generate fingerprint
            fp = self.fingerprinter.generate_fingerprint(formatted_data)
            encoded_fingerprint = self.fingerprinter.encode_fingerprint(fp)
            print("encoded_fingerprint:", encoded_fingerprint)
            
            # Search for fingerprint in database
            existing_fp = session.query(Fingerprint).filter_by(fingerprint=encoded_fingerprint).first()
            print("existing_fp:", existing_fp)
            
            return existing_fp is not None
            
        except Exception as e:
            print(f"Error during fingerprint verification: {e}")
            return False
        finally:
            session.close()

    def add_user_to_db(self, first_name: str, last_name: str, passport: str, series: str) -> dict:
        """
        Add a new verified user to the fingerprint database
        
        Args:
            
            first_name: User's first name
            last_name: User's last name
            passport: Passport number
            series: Passport series
        
        Returns:
            Dictionary with operation result
        """
        session = self.Session()
        
        try:
            # Format the data
            formatted_data = self.format_user_data( first_name, last_name, passport, series)
            
            # Generate fingerprint
            fp = self.fingerprinter.generate_fingerprint(formatted_data)
            encoded_fingerprint = self.fingerprinter.encode_fingerprint(fp)

            # Check if fingerprint already exists
            existing_fp = session.query(Fingerprint).filter_by(fingerprint=encoded_fingerprint).first()
            if existing_fp:
                return {
                    "status": "already_exists",
                    "message": "User already verified",
                    "database_id": existing_fp.id,
                    "formatted_data": formatted_data
                }

            # Add new fingerprint
            new_fp = Fingerprint(fingerprint=encoded_fingerprint)
            session.add(new_fp)
            session.commit()

            return {
                "status": "added",
                "message": "User added to verified database",
                "database_id": new_fp.id,
                "formatted_data": formatted_data,
                "fingerprint": encoded_fingerprint
            }

        except Exception as e:
            session.rollback()
            return {
                "status": "error",
                "message": f"Error adding user: {str(e)}"
            }
        finally:
            session.close()

    def verify_user_data(self, first_name: str, last_name: str, passport: str, series: str) -> dict:
        """
        Complete verification process: format data, generate fingerprint, and verify against database
        
        Args:
            first_name: User's first name
            last_name: User's last name
            passport: Passport number
            series: Passport series
        
        Returns:
            Dictionary with verification result
        """
        try:
            # Format the data
            formatted_data = self.format_user_data( first_name, last_name, passport, series)
            
            # Verify against database
            is_verified = self.verify_fingerprint_in_db(formatted_data)
            
            return {
                "verified": is_verified,
                "formatted_data": formatted_data,
                "message": "User verified successfully" if is_verified else "User not found in verified database"
            }
            
        except Exception as e:
            return {
                "verified": False,
                "error": str(e),
                "message": "Error during verification process"
            }

    def get_database_stats(self) -> dict:
        """
        Get statistics about the fingerprint database
        
        Returns:
            Dictionary with database statistics
        """
        session = self.Session()
        try:
            total_count = session.query(Fingerprint).count()
            return {
                "total_verified_users": total_count,
                "database_status": "connected"
            }
        except Exception as e:
            return {
                "error": f"Database error: {str(e)}",
                "database_status": "error"
            }
        finally:
            session.close()
        
    def register_user(self, data: str) -> str:
        """
        Register a new user in the system (original method for backward compatibility).
        
        Args:
            data: User's identification data (lowercase, no spaces)
            
        Returns:
            User's unique identifier
        """
        # Generate fingerprint
        fingerprint = self.fingerprinter.generate_fingerprint(data)
        encoded = self.fingerprinter.encode_fingerprint(fingerprint)
        
        # Generate unique user ID
        user_id = hashlib.sha256(f"{data}:{secrets.token_hex(8)}".encode()).hexdigest()[:12]
        
        # Store in database
        self.user_db[user_id] = {
            'fingerprint': encoded,
        }
        
        return user_id
    
    def verify_user(self, data: str, user_id: str) -> bool:
        """
        Verify a user's identity (original method for backward compatibility).
        
        Args:
            data: User's identification data (lowercase, no spaces)
            user_id: User's unique identifier
            
        Returns:
            True if verification succeeds, False otherwise
        """
        # Check if user exists
        if user_id not in self.user_db:
            return False
            
        # Get stored fingerprint
        stored_fingerprint = self.user_db[user_id]['fingerprint']
        
        # Verify fingerprint
        return self.fingerprinter.verify_fingerprint(data, stored_fingerprint)