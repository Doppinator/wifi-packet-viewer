from datetime import datetime


def print_header(start_time):
    print("\n" + "=" * 60)
    print(f"Capture started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


def print_footer(start_time, end_time, packet_count):
    print("=" * 60)
    print(f"Capture ended: {end_time.strftime('%H:%M:%S')}")
    print(f"Total packets captured: {packet_count}")
    print(f"Duration: {(end_time - start_time).total_seconds():.2f} seconds")
    print("=" * 60)


def timestamp():
    return datetime.now().strftime("%H:%M:%S")