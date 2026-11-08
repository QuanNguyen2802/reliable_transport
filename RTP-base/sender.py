
import argparse
import socket
import sys
import time

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472
MAX_PAYLOAD_SIZE = MAX_PACKET_SIZE - HEADER_SIZE
TIMEOUT = 0.5


def create_packet(packet_type, seq_num, payload=b""):
    """Create a packet and calculate its checksum."""

    pkt_header = PacketHeader(
        type=packet_type,
        seq_num=seq_num,
        length=len(payload),
        checksum=0
    )

    pkt = pkt_header / payload
    pkt_header.checksum = compute_checksum(pkt)

    return bytes(pkt_header / payload)


def parse_ack(pkt):
    """Check ACK packet and return its sequence number."""

    if len(pkt) != HEADER_SIZE:
        return None

    pkt_header = PacketHeader(pkt[:HEADER_SIZE])

    if pkt_header.type != 3 or pkt_header.length != 0:
        return None

    received_checksum = pkt_header.checksum
    pkt_header.checksum = 0

    if compute_checksum(pkt_header) != received_checksum:
        return None

    return pkt_header.seq_num


def receive_ack(sock, receiver, deadline):
    """Wait for a valid ACK until the deadline."""

    expected_ip = socket.gethostbyname(receiver[0])

    while True:
        remaining = deadline - time.monotonic()

        if remaining <= 0:
            return None

        sock.settimeout(remaining)

        try:
            packet, address = sock.recvfrom(2048)
        except (socket.timeout, OSError):
            return None

        # Check source IP, but do not require the same UDP port.
        if address[0] != expected_ip:
            continue

        ack_seq = parse_ack(packet)

        if ack_seq is not None:
            return ack_seq


def sender(receiver_ip, receiver_port, window_size):
    """Send message from stdin using reliable UDP."""

    if window_size <= 0:
        raise ValueError("window_size must be positive")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver = (receiver_ip, receiver_port)

    try:
        # 1. Read message from stdin
        message = sys.stdin.buffer.read()

        # 2. Split message into chunks
        chunks = [
            message[i:i + MAX_PAYLOAD_SIZE]
            for i in range(0, len(message), MAX_PAYLOAD_SIZE)
        ]

        total_packets = len(chunks)

        # 3. Send START packet
        start_pkt = create_packet(0, 0)

        s.sendto(start_pkt, receiver)

        while True:
            start_deadline = time.monotonic() + TIMEOUT
            ack = receive_ack(s, receiver, start_deadline)

            if ack == 1:
                break

            if ack is None:
                s.sendto(start_pkt, receiver)

        # 4. Initialize sliding window
        base = 1
        next_seq = 1

        # Store packets that have not been acknowledged
        window = {}

        timer = None

        # 5. Send DATA packets
        while base <= total_packets:

            # Fill the sending window
            while (
                next_seq <= total_packets
                and next_seq < base + window_size
            ):
                payload = chunks[next_seq - 1]

                pkt = create_packet(
                    2,
                    next_seq,
                    payload
                )

                s.sendto(pkt, receiver)

                window[next_seq] = pkt

                if timer is None:
                    timer = time.monotonic() + TIMEOUT

                next_seq += 1

            # Wait for ACK
            ack_seq = receive_ack(s, receiver, timer)

            # 6. Timeout: retransmit all unacknowledged packets
            if ack_seq is None:

                for pkt in window.values():
                    s.sendto(pkt, receiver)

                timer = time.monotonic() + TIMEOUT
                continue

            # 7. Process cumulative ACK
            if base < ack_seq <= next_seq:

                # Move the window forward
                base = ack_seq

                # Remove acknowledged packets
                for seq in list(window.keys()):
                    if seq < base:
                        del window[seq]

                # Reset timer
                if window:
                    timer = time.monotonic() + TIMEOUT
                else:
                    timer = None

        # 8. Send END packet
        end_seq = total_packets + 1

        end_pkt = create_packet(1, end_seq)

        s.sendto(end_pkt, receiver)

        # Wait for END ACK or 500 milliseconds
        end_deadline = time.monotonic() + TIMEOUT

        while time.monotonic() < end_deadline:

            ack = receive_ack(s, receiver, end_deadline)

            if ack == end_seq + 1:
                break

            if ack is None:
                break

    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "receiver_ip",
        help="The IP address of the host that receiver is running on"
    )

    parser.add_argument(
        "receiver_port",
        type=int,
        help="The port number on which receiver is listening"
    )

    parser.add_argument(
        "window_size",
        type=int,
        help="Maximum number of outstanding packets"
    )

    args = parser.parse_args()

    sender(args.receiver_ip, args.receiver_port, args.window_size)


if __name__ == "__main__":
    main()
