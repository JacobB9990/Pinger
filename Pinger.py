from socket import *
import sys, os, time, struct, select, statistics

ICMP_ECHO_REQUEST = 8
statsList = []
seq = 0
packetLost = 0
userInput = sys.argv


def endMessage(host, dest):
    print(f'--- {host} ping statistics ---')
    print(packetLoss(1))
    if len(statsList) == 0:
        sys.exit(0)
    else:
        print(findStats(statsList, dest))
        sys.exit()


def getCount(command):
    command = sys.argv
    if "-c" in command:
        return int(command[command.index("-c") + 1])


def displayHelp():
    print(f'usage: Pinger <hostname> [options]\n\nOptions:\n\t--help, -h\tShow this help message\n\t-c,       \tCount')


def increaseSequence():
    global seq
    seq += 1
    return seq


def packetLoss(code=0):
    global packetLost
    if code == 1:
        try:
            return (f'{seq} packets transmitted, {len(statsList)} packets received, {(packetLost / seq) * 100}% '
                    f'packet loss')
        except ZeroDivisionError:
            print(f'A zero-division error occurred')
    else:
        packetLost += 1


def checksum(source_string):
    csum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        csum += this_val
        count += 2

    if count_to < len(source_string):
        csum += source_string[-1]

    csum = (csum >> 16) + (csum & 0xffff)
    csum += (csum >> 16)
    answer = ~csum & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def recvOnePing(mySocket, ID, timeout, destAddr):
    time_left = timeout

    while True:
        started_select = time.time()
        what_ready = select.select([mySocket], [], [], time_left)
        how_long_in_select = (time.time() - started_select)

        if what_ready[0] == []:
            packetLoss(0)
            return f"Request timed out for icmp_seq={increaseSequence()}"

        time_received = time.time()
        rec_packet, addr = mySocket.recvfrom(1024)

        icmp_header = rec_packet[20:28]
        type, code, checksum, packet_ID, sequence = struct.unpack("bbHHh", icmp_header)

        if packet_ID == ID:
            time_sent = struct.unpack("d", rec_packet[28:28 + struct.calcsize("d")])[0]
            delay = (time_received - time_sent) * 1000
            statsList.append(delay)
            return f"{len(rec_packet)} bytes from {destAddr}: icmp_seq={increaseSequence()} time={delay:.2f} ms"

        time_left -= how_long_in_select
        if time_left <= 0:
            packetLoss(0)
            return f"Request timed out for icmp_seq={increaseSequence()}"


def sendOnePing(mySocket, destAddr, ID):
    my_checksum = 0
    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    data = struct.pack("d", time.time())
    my_checksum = checksum(header + data)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, htons(my_checksum), ID, 1)
    packet = header + data

    mySocket.sendto(packet, (destAddr, 1))


def doOnePing(destAddr, timeout):
    icmp = getprotobyname("icmp")
    try:
        mySocket = socket(AF_INET, SOCK_RAW, icmp)
    except PermissionError as e:
        return f"Operation not permitted: {e}. Run with elevated privileges."

    myID = os.getpid() & 0xFFFF

    sendOnePing(mySocket, destAddr, myID)
    delay = recvOnePing(mySocket, myID, timeout, destAddr)

    mySocket.close()
    return delay


def findStats(list, dest):
    minimum = min(list)
    maximum = max(list)
    average = sum(list) / len(list)

    if len(list) > 1:
        stddev = statistics.stdev(list)
        stddev = f'{stddev:.2f}'
    else:
        stddev = "nan"

    return f'round-trip min/avg/max/stddev: {minimum:.2f}/{average:.2f}/{maximum:.2f}/{stddev} ms'


def ping(host, timeout=1, count=5):
    global dest
    dest = host

    nCount = 0
    try:
        dest = gethostbyname(host)
    except gaierror:
        print(f"Pinger: cannot resolve {host}: Unknown host")
        sys.exit(0)

    print(f"Pinging {host} ({dest}):")

    try:
        while count == 0 or nCount < count:
            nCount += 1

            start_time = time.time()
            delay = doOnePing(dest, timeout)
            print(delay)
            elapsed_time = time.time() - start_time
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

    if len(userInput) > 2:
        if "-c" in userInput:
            ping(hostInp, count=getCount(userInput))
        elif "-h" in userInput or "--help" in userInput:
            displayHelp()
        else:
            print(f'invalid option: {userInput[2]}')
            displayHelp()

    else:
        ping(hostInp)
