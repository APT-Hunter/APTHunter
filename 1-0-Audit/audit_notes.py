"""
auditctl - Used to control the behaviors, get status, and add or delete rules.

Options:

    enable (-e) [0..2] -- 0 can be passed to temporarily disable auditing (1 enables).
    -m test -- Send a userspace message into audit logs.
    -l (list) -- List all rules 1 per line.
    -k (key) - Set a filter key on audit rules.
"""
