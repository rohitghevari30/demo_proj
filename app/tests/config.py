import os
db_password = os.environ.get("DB_PASSWORD", "")
SECRET_KEY = os.environ.get("SECRET_KEY", "")
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY", "")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_KEY", "")