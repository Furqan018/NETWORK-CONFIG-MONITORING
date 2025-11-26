import hashlib
import json
import time
from typing import Dict, List, Optional
from cryptography.fernet import Fernet
import base64

class NetworkConfigManager:
    def __init__(self):
        self.config_key = self._generate_key()
        self.cipher_suite = Fernet(self.config_key)
    
    def _generate_key(self) -> bytes:
        return Fernet.generate_key()
    
    def calculate_config_hash(self, config_data: Dict) -> str:
        """Calculate SHA-256 hash of configuration data"""
        config_string = json.dumps(config_data, sort_keys=True)
        return hashlib.sha256(config_string.encode()).hexdigest()
    
    def encrypt_config(self, config_data: Dict) -> str:
        """Encrypt configuration data"""
        config_string = json.dumps(config_data)
        encrypted_data = self.cipher_suite.encrypt(config_string.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_config(self, encrypted_config: str) -> Dict:
        """Decrypt configuration data"""
        encrypted_data = base64.urlsafe_b64decode(encrypted_config.encode())
        decrypted_data = self.cipher_suite.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())
    
    def validate_config_change(self, old_config: Dict, new_config: Dict) -> Dict:
        """Validate configuration changes and return change details"""
        changes = {
            "added": {},
            "modified": {},
            "removed": {},
            "is_valid": True
        }
        
        # Check for modifications and additions
        for key, new_value in new_config.items():
            if key not in old_config:
                changes["added"][key] = new_value
            elif old_config[key] != new_config[key]:
                changes["modified"][key] = {
                    "old": old_config[key],
                    "new": new_value
                }
        
        # Check for removals
        for key in old_config:
            if key not in new_config:
                changes["removed"][key] = old_config[key]
        
        return changes
    
    def create_config_record(self, device_name: str, config_data: Dict, 
                           change_description: str, author: str) -> Dict:
        """Create a standardized configuration record for blockchain"""
        config_hash = self.calculate_config_hash(config_data)
        
        return {
            "device_name": device_name,
            "config_hash": config_hash,
            "config_data_encrypted": self.encrypt_config(config_data),
            "change_description": change_description,
            "author": author,
            "timestamp": time.time(),
            "config_size": len(json.dumps(config_data))
        }