from config import Config

# Server socket
bind = "0.0.0.0:10000"
backlog = 2048

# Worker processes
workers = Config.WORKERS
worker_class = Config.WORKER_CLASS
threads = Config.THREADS
timeout = Config.TIMEOUT

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"

# Process naming
proc_name = "genhub_backend"

# SSL (if needed)
# keyfile = 'path/to/keyfile'
# certfile = 'path/to/certfile'

# Maximum number of requests a worker will process before restarting
max_requests = 1000
max_requests_jitter = 50

# Limit worker memory usage
limit_request_line = 0
limit_request_fields = 100
limit_request_field_size = 8190 