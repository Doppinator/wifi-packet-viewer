from datetime import datetime


conversation_counter = 0
conversations = {}


def track_conversation(endpoint1, endpoint2):
    global conversation_counter

    conversation = tuple(sorted([endpoint1, endpoint2]))

    if conversation not in conversations:
        conversation_counter += 1
        conversations[conversation] = {
            "id": conversation_counter,
            "count": 1,
            "state": "NEW",
            "last_seen": datetime.now(),
        }
    else:
        conversations[conversation]["count"] += 1
        conversations[conversation]["last_seen"] = datetime.now()

    return conversations[conversation]