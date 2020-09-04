import uuid, socket

print(uuid.UUID(int = uuid.getnode()).hex[-12:])
print(socket.gethostname())