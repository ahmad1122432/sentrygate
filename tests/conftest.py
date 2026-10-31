import os, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
os.environ["SENTRY_DB"] = os.path.join(tempfile.mkdtemp(), "test.db")  # never touch the real log
