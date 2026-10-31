
import argparse
import socket
import sys

from utils import PacketHeader, compute_checksum


HEADER_SIZE = 16
MAX_PACKET_SIZE = 1472


def parse_packet(pkt):
    """Extract packet header and payload, then verify checksum."""

    if len(pkt) < HEADER_SIZE:
        return None

    pkt_header = PacketHeader(pkt[:HEADER_SIZE])
    msg = pkt[HEADER_SIZE:]

    if pkt_header.length != len(msg):
        return None

    pkt_checksum = pkt_header.checksum
    pkt_header.checksum = 0

    computed_checksum = compute_checksum(pkt_header / msg)

    if pkt_checksum != computed_checksum:
        return None

    return pkt_header, msg


def send_ack(s, address, seq_num):
    """Create and send an ACK packet."""

    pkt_header = PacketHeader(
        type=3,
        seq_num=seq_num,
        length=0,
        checksum=0
    )

    pkt_header.checksum = compute_checksum(pkt_header)

    s.sendto(bytes(pkt_header), address)


def receiver(receiver_ip, receiver_port, window_size):
    """Listen on socket and print received message to sys.stdout."""

    if window_size <= 0:
        raise ValueError("window_size must be positive")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((receiver_ip, receiver_port))

    active = False
    sender_address = None

    # Next expected sequence number
    expected = 1

    # Store packets received out of order
    buffer = {}

    try:
        while True:

            pkt, address = s.recvfrom(MAX_PACKET_SIZE)

            result = parse_packet(pkt)

            # Drop invalid or corrupted packets
            if result is None:
                continue

            pkt_header, msg = result

            # --------------------------------
            # 1. Handle START packet
            # --------------------------------

            if pkt_header.type == 0:

                # Ignore START during an active connection
                if active:
                    continue

                if pkt_header.seq_num != 0 or pkt_header.length != 0:
                    continue

                active = True
                sender_address = address

                expected = 1
                buffer = {}

                # ACK for START
                send_ack(s, sender_address, 1)

                continue

            # Ignore packets from other senders
            if not active or address != sender_address:
                continue

            # --------------------------------
            # 2. Handle DATA packet
            # --------------------------------

            if pkt_header.type == 2:

                seq_num = pkt_header.seq_num

                # Duplicate packet
                if seq_num < expected:
                    send_ack(s, sender_address, expected)
                    continue

                # Packet outside receiving window
                if seq_num >= expected + window_size:
                    continue

                # Buffer out-of-order packet
                if seq_num not in buffer:
                    buffer[seq_num] = msg

                # Deliver consecutive packets in order
                while expected in buffer:

                    data = buffer.pop(expected)

                    sys.stdout.buffer.write(data)

                    expected += 1

                sys.stdout.buffer.flush()

                # Send cumulative ACK
                send_ack(s, sender_address, expected)

            # --------------------------------
            # 3. Handle END packet
            # --------------------------------

            elif pkt_header.type == 1:

                if pkt_header.length != 0:
                    continue

                if pkt_header.seq_num == expected:

                    # ACK for END
                    send_ack(
                        s,
                        sender_address,
                        pkt_header.seq_num + 1
                    )

                    sys.stdout.buffer.flush()

                    break

                else:
                    send_ack(s, sender_address, expected)

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

    receiver(
        args.receiver_ip,
        args.receiver_port,
        args.window_size
    )


if __name__ == "__main__":
    main()
