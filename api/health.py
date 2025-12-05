"""
Minimal health-check handler to confirm Vercel runtime execution.
"""


def handler(event, context):
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "text/plain",
        },
        "body": "ok",
    }


