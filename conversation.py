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
        }
    else:
        conversations[conversation]["count"] += 1

    return conversations[conversation]