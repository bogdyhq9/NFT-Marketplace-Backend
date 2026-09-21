import numpy as np
from typing import List, Union, Tuple
import hashlib  # For comparison with standard hash algorithms

class BipermutativeCA:
    """
    A class implementing bipermutative radius-2 cellular automata
    """
    
    def __init__(self, rule_number: int, width: int = 128):
        """
        Initialize the CA with a specific rule number and array width.
        
        Args:
            rule_number: Integer representing the CA rule (0 to 2^32-1)
            width: Width of the CA array
        """
        self.rule_number = rule_number
        self.width = width
        self.radius = 2
        self.lookup_table = self._create_lookup_table()
        self.current_state = None
        
    def _create_lookup_table(self) -> List[int]:
        """Create a lookup table for the CA rule."""
        table = []
        for i in range(2**(2*self.radius + 1)):
            # Extract bit i from rule_number
            output = (self.rule_number >> i) & 1
            table.append(output)
        return table
    
    def initialize_state(self, state: Union[List[int], np.ndarray]) -> np.ndarray:
        """Initialize the CA state."""
        if len(state) != self.width:
            # Handle different input lengths by padding or truncating
            padded_state = np.zeros(self.width, dtype=np.int8)
            for i in range(min(len(state), self.width)):
                padded_state[i] = state[i]
            self.current_state = padded_state
        else:
            self.current_state = np.array(state, dtype=np.int8)
        return self.current_state
    
    def get_neighborhood_value(self, state: np.ndarray, pos: int) -> int:
        """Calculate the neighborhood value at a given position."""
        value = 0
        for i in range(-self.radius, self.radius + 1):
            # Circular boundary conditions
            idx = (pos + i) % self.width
            value = (value << 1) | state[idx]
        return value
    
    def step(self) -> np.ndarray:
        """Evolve the CA one step forward."""
        new_state = np.zeros_like(self.current_state)
        
        for i in range(self.width):
            neighborhood = self.get_neighborhood_value(self.current_state, i)
            new_state[i] = self.lookup_table[neighborhood]
            
        self.current_state = new_state
        return new_state


class CAHashFunction:
    """
    A hash function implementation using multiple bipermutative CA rules.
    """
    
    def __init__(self, width: int = 128, output_size: int = 32):
        """
        Initialize the hash function.
        
        Args:
            width: Width of the CA array
            output_size: Size of the hash output in bytes
        """
        self.width = width
        self.output_size = output_size
        self.rules = {
            'r1': 1452976485,  # Rule 1
            'r2': 1520018790,  # Rule 2
            'r3': 2778290790,  # Rule 3
            'r4': 1436194405   # Rule 4
        }
        self.ca_instances = {
            rule_name: BipermutativeCA(rule_number, width) 
            for rule_name, rule_number in self.rules.items()
        }
        
    def _preprocess_input(self, data: Union[str, bytes, List[int]]) -> List[int]:
        """Convert input data to bits."""
        if isinstance(data, str):
            # Convert string to bytes
            data = data.encode('utf-8')
            
        if isinstance(data, bytes):
            # Convert bytes to bits
            bits = []
            for byte in data:
                for i in range(7, -1, -1):
                    bits.append((byte >> i) & 1)
            return bits
        elif isinstance(data, list):
            # Assume it's already a list of bits
            return data
        else:
            raise ValueError("Unsupported input type")
    
    def _postprocess_output(self, state: np.ndarray) -> bytes:
        """Convert CA state to hash output."""
        # Extract output_size bytes from the CA state
        result = bytearray()
        for i in range(0, min(self.width, self.output_size * 8), 8):
            byte_val = 0
            for j in range(8):
                if i + j < self.width:
                    byte_val = (byte_val << 1) | state[i + j]
            result.append(byte_val)
            
        # If we need more bytes, we can cycle through the state again
        while len(result) < self.output_size:
            for i in range(0, self.width, 8):
                if len(result) >= self.output_size:
                    break
                byte_val = 0
                for j in range(8):
                    if i + j < self.width:
                        byte_val = (byte_val << 1) | state[i + j]
                result.append(byte_val)
                
        return bytes(result)

    def hash(self, data: Union[str, bytes, List[int]]) -> bytes:
        """
        Hash the input data using alternating CA rules.
        
        Args:
            data: Input data to hash
            
        Returns:
            Hash value as bytes
        """
        # Convert input to bits
        bits = self._preprocess_input(data)
        
        # Initialize state with input bits (padded or truncated to match width)
        state = np.zeros(self.width, dtype=np.int8)
        for i in range(min(len(bits), self.width)):
            state[i] = bits[i]
            
        # Define rule sequences for each iteration
        rule_sequences = [
            ['r3', 'r1', 'r4', 'r2', 'r2', 'r4', 'r3', 'r1', 'r4', 'r3', 'r1', 'r2'],
            ['r2', 'r4', 'r1', 'r3', 'r4', 'r1', 'r2', 'r3', 'r1', 'r4', 'r3', 'r2'],
            ['r4', 'r2', 'r3', 'r1', 'r3', 'r2', 'r4', 'r1', 'r2', 'r3', 'r1', 'r4']
        ]
        
        # Perform iterations with alternating rules
        for iteration, rule_sequence in enumerate(rule_sequences):
            # Apply each rule in the sequence
            for rule_name in rule_sequence:
                ca = self.ca_instances[rule_name]
                ca.initialize_state(state)
                state = ca.step()
                
            # After each iteration, perform a mixing operation
            # This helps ensure good avalanche effect between iterations
            # XOR the first half with the second half
            half_width = self.width // 2
            for i in range(half_width):
                state[i] ^= state[i + half_width]
                # And propagate changes back to second half
                state[i + half_width] ^= state[i]
        
        # Convert final state to hash output
        return self._postprocess_output(state)
    
    def hash_hex(self, data: Union[str, bytes, List[int]]) -> str:
        """Return the hash as a hexadecimal string."""
        hash_bytes = self.hash(data)
        return hash_bytes.hex()