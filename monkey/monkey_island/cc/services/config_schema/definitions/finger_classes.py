FINGER_CLASSES = {
    "title": "Fingerprinters",
    "description": "Fingerprint modules collect info about external services "
    "Infection Monkey scans.",
    "type": "string",
    "anyOf": [
        {
            "type": "string",
            "enum": ["SMBFinger"],
            "title": "SMB Fingerprinter",
            "safe": True,
            "info": "Figures out if SMB is running and what's the version of it.",
            "attack_techniques": ["T1210"],
        },
        {
            "type": "string",
            "enum": ["SSHFinger"],
            "title": "SSH Fingerprinter",
            "safe": True,
            "info": "Figures out if SSH is running.",
            "attack_techniques": ["T1210"],
        },
        {
            "type": "string",
            "enum": ["PingScanner"],
            "title": "Ping Scanner",
            "safe": True,
            "info": "Tries to identify if host is alive and which OS it's running by ping scan.",
        },
        {
            "type": "string",
            "enum": ["HTTPFinger"],
            "title": "HTTP Fingerprinter",
            "safe": True,
            "info": "Checks if host has HTTP/HTTPS ports open.",
        },
        {
            "type": "string",
            "enum": ["MySQLFinger"],
            "title": "MySQL Fingerprinter",
            "safe": True,
            "info": "Checks if MySQL server is running and tries to get it's version.",
            "attack_techniques": ["T1210"],
        },
        {
            "type": "string",
            "enum": ["MSSQLFinger"],
            "title": "MSSQL Fingerprinter",
            "safe": True,
            "info": "Checks if Microsoft SQL service is running and tries to gather "
            "information about it.",
            "attack_techniques": ["T1210"],
        },
        {
            "type": "string",
            "enum": ["ElasticFinger"],
            "title": "Elastic Fingerprinter",
            "safe": True,
            "info": "Checks if ElasticSearch is running and attempts to find it's " "version.",
            "attack_techniques": ["T1210"],
        },
    ],
}
