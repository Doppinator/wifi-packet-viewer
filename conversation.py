from datetime import datetime

conversation_counter = 0
conversations = {}


# Tracks traffic conversations between two endpoints, updating the conversation count and state
def track_conversation(endpoint1, endpoint2):
    global conversation_counter

    conversation = tuple(sorted([endpoint1, endpoint2]))

    if conversation not in conversations:
        # If this is a new conversation, increment the counter and initialize its state
        conversation_counter += 1
        conversations[conversation] = {
            "id": conversation_counter,
            "count": 1,
            "state": "NEW",
            "last_seen": datetime.now(),
        }
    else:
        conversations[conversation]["count"] += (
            1  # If not new increment the count of packets in this conversation
        )
        conversations[conversation]["last_seen"] = (
            datetime.now()
        )  # Update the last seen timestamp for this conversation

    return conversations[conversation]
