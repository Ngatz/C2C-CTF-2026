import jwt
from datetime import datetime, timedelta, timezone

JWT_SECRET = '8fbdbc29fa8af9530cdac2e68261c02f7e245b3c805fa6725b6cd36c97b694f9'

token = jwt.encode({
    'user_id': 4,
    'username': 'mike.wilson',
    'is_admin': 0,
    'exp': datetime.now(timezone.utc) + timedelta(days=7)
}, JWT_SECRET, algorithm='HS256')

print(token)
