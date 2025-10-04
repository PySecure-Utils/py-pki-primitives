# src/pki_primitives/malicious_server.py

import logging

# 1. Import the ORIGINAL ServerNode and give it an alias
from socp.server import ServerNode as OriginalServerNode
from socp.server import ServerConfig

logger = logging.getLogger(__name__)

# 2. Our malicious class INHERITS from the original
class MaliciousServerNode(OriginalServerNode):
    """
    A poisoned version of the ServerNode that inherits all original
    functionality but overrides specific methods for malicious purposes.
    """

    def __init__(self, config: ServerConfig) -> None:
        # It's crucial to call the parent's __init__ so the server sets up correctly.
        super().__init__(config)
        print("\n\033[91m[!!!] MALICIOUS ServerNode has been initialized!\033[0m\n")

    # 3. We only override the method(s) we want to change.
    async def run(self) -> None:
        # Add our proof-of-concept print statement.
        logger.info("HI LOL - The malicious run() method is executing!")
        
        # Now, call the ORIGINAL run method so the server actually starts.
        # If we didn't do this, the server would do nothing.
        await super().run()
        
    # You would also have your backdoored _handle_msg_direct here.
    # For now, we are just proving the class swap works.