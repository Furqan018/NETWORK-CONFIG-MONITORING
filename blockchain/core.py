import hashlib
import json
import time
from typing import List, Dict, Any
from cryptography.fernet import Fernet
import base64

class Block:
    def __init__(self, index: int, timestamp: float, data: Dict, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self) -> str:
        block_string = json.dumps({
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()
    
    def mine_block(self, difficulty: int):
        while self.hash[:difficulty] != "0" * difficulty:
            self.nonce += 1
            self.hash = self.calculate_hash()

class Blockchain:
    def __init__(self):
        self.chain: List[Block] = [self.create_genesis_block()]
        self.difficulty = 4
        self.pending_transactions = []
    
    def create_genesis_block(self) -> Block:
        return Block(0, time.time(), {"message": "Genesis Block"}, "0")
    
    def get_latest_block(self) -> Block:
        return self.chain[-1]
    
    def add_block(self, data: Dict) -> bool:
        latest_block = self.get_latest_block()
        new_block = Block(
            index=len(self.chain),
            timestamp=time.time(),
            data=data,
            previous_hash=latest_block.hash
        )
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)
        return True
    
    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            if current_block.hash != current_block.calculate_hash():
                return False
            
            if current_block.previous_hash != previous_block.hash:
                return False
        
        return True
    
    def get_chain_data(self) -> List[Dict]:
        return [{
            "index": block.index,
            "timestamp": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(block.timestamp)),
            "data": block.data,
            "previous_hash": block.previous_hash,
            "hash": block.hash,
            "nonce": block.nonce
        } for block in self.chain]