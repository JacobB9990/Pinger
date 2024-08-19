import os
import select
import statistics
import struct
import sys
import time
from socket import *
from typing import List, Optional

ICMP_ECHO_REQUEST: int = 8
statsList: List[float] = []
seq: int = 0
packetLost: float = 0
userInput: List[str] = sys.argv


def endMessage(host: str, dest: str) -> None:
    print(f'--- {host} ping statistics ---')
    print(packetLoss(1))
    if len(statsList) == 0:
        sys.exit(0)
    else:
        print(findStats(statsList, dest))
        sys.exit()


def getCount(command: List[str]) -> int:
    if "-c" in command:
        return int(command[command.index("-c") + 1])
    return 0


def displayHelp() -> None:
    print(f'usage: Pinger <hostname> [options]\n\nOptions:\n\t--help, -h\tShow this help message\n\t-c,       \tCount')


def increaseSequence() -> int:
    global seq
    seq += 1
    return seq


def packetLoss(code: int = 0) -> Optional[str]:
    global packetLost
    if code == 1:
        try:
            return (f'{seq} packets transmitted, {len(statsList)} packets received, {(packetLost / seq) * 100}% '
                    f'packet loss')
        except ZeroDivisionError:
            print(f'A zero-division error occurred')
    else:
        packetLost += 1
    return None


def checksum(source_string: bytes) -> int:
    csum: int = 0
    count_to: int = (len(source_string) // 2) * 2
    count: int = 0

    while count < count_to:
        this_val: int = source_string[count + 1] * 256 + source_string[count]
        csum += this_val
        count += 2

    if count_to < len(source_string):
        csum += source_string[-1]

    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)
    answer: int = ~csum & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def recvOnePing(mySocket: socket, ID: int, timeout: int, destAddr: str) -> str:
    time_left: float = timeout

    while True:
        started_select: float = time.time()
        what_ready = select.select([mySocket], [], [], time_left)
        how_long_in_select: float = time.time() - started_select

        if not what_ready[0]:
            packetLoss(0)
            return f"Request timed out for icmp_seq={increaseSequence()}"

        time_received: float = time.time()
        rec_packet: bytes
        addr: tuple
        rec_packet, addr = mySocket.recvfrom(1024)

        ip_header: bytes = rec_packet[:20]
        ttl: int = ip_header[8]

        icmp_header: bytes = rec_packet[20:28]
        type, code, checksum_val, packet_ID, sequence = struct.unpack("bbHHh", icmp_header)

        if packet_ID == ID:
            time_sent: float = struct.unpack("d", rec_packet[28:28 + struct.calcsize("d")])[0]
            delay: float = (time_received - time_sent) * 1000
            statsList.append(delay)
            return f"{len(rec_packet)} bytes from {destAddr}: icmp_seq={increaseSequence()} ttl={ttl} time={delay:.2f} ms"

        time_left -= how_long_in_select
        if time_left <= 0:
            packetLoss(0)
            return f"Request timed out for icmp_seq={increaseSequence()}"


def sendOnePing(mySocket: socket, destAddr: str, ID: int) -> None:
    my_checksum: int = 0
    header: bytes = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    data: bytes = struct.pack("d", time.time())
    my_checksum = checksum(header + data)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, htons(my_checksum), ID, 1)
    packet: bytes = header + data

    mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr: str, timeout: int) -> str:
    icmp: int = getprotobyname("icmp")
    try:
        mySocket: socket = socket(AF_INET, SOCK_DGRAM, icmp)
    except PermissionError as e:
        return f"Operation not permitted: {e}. Run with elevated privileges."

    myID: int = os.getpid() & 0xFFFF

    sendOnePing(mySocket, destAddr, myID)
    delay: str = recvOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def findStats(list: List[float], dest: str) -> str:
    minimum: float = min(list)
    maximum: float = max(list)
    average: float = sum(list) / len(list)

    if len(list) > 1:
        stddev: float = statistics.stdev(list)
        stddev = round(stddev, 3)
    else:
        stddev: str = "nan"

    return f'round-trip min/avg/max/stddev: {minimum:.3f}/{average:.3f}/{maximum:.3f}/{stddev} ms'


def ping(host: str, timeout: int = 1, count: int = 0) -> None:
    nCount: int = 0
    try:
        dest = gethostbyname(host)
    except gaierror:
        print(f"Pinger: cannot resolve {host}: Unknown host")
        sys.exit(0)

    print(f"Pinging {host} ({dest}):")

    try:
        while count == 0 or nCount < count:
            nCount += 1

            start_time: float = time.time()
            delay: str = doOnePing(dest, timeout)
            print(delay)
            elapsed_time: int = int(time.time() - start_time)
            time.sleep(max(0, 1 - elapsed_time))

        endMessage(host, dest)

    except KeyboardInterrupt:
        print()
        endMessage(host, dest)

    except Exception as e:
        print(f"\nPinger: other error: {e}")


if __name__ == "__main__":
    if len(userInput) == 1:
        displayHelp()
        sys.exit(0)

    hostInp: str = userInput[1]

    if len(userInput) >= 2:
        if "-c" in userInput:
            try:
                ping(hostInp, count=getCount(userInput))
            except IndexError:
                displayHelp()
        elif "-h" in userInput or "--help" in userInput:
            displayHelp()
        else:
            ping(hostInp, count=getCount(userInput))

    else:
        ping(hostInp)
