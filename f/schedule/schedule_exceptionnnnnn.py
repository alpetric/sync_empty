# Schedule handler script
# This script validates scheduled datetimes for schedules
# Return True to accept the datetime, False to skip to the next occurrence

def main(scheduled_for: str) -> bool:
    # scheduled_for is an ISO8601 datetime string, e.g. "2025-09-30T12:00:00Z"
    
    from datetime import datetime
    
    # Parse the ISO8601 datetime string
    dt = datetime.fromisoformat(scheduled_for.replace('Z', '+00:00'))
    
    # Return True if minute is even, False if minute is odd
    # return dt.minute % 2 == 0
    return 1/0 == 0
