"""python -m guardrails.audit_cli verify FILE   (key from env GR_AUDIT_KEY)"""
import sys

from guardrails.audit import _main

if __name__ == "__main__":
    sys.exit(_main(sys.argv))
