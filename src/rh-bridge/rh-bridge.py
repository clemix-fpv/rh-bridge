#!/usr/bin/env python3

import sys
import socket
import threading
import argparse
import serial
import time
import logging
from msp import MSPPacket, MSPTypes, MSPPacketType

logging_level = logging.DEBUG
stop_event = threading.Event()


def create_logger(name=""):
    if len(name) > 0:
        name = name + " "
    logger = logging.getLogger(name)
    if not logger.hasHandlers():
        logger.setLevel(logging_level)
        formatter = logging.Formatter("%(name)s%(levelname)s - %(message)s")

        stream_handler = logging.StreamHandler()
        stream_handler.setFormatter(formatter)

        logger.addHandler(stream_handler)
    return logger


def pkt2str(pkg: MSPPacket):
    s = "{:8} ".format(pkg.type_.name)
    if (pkg._flags > 0):
        s += "flags:{} ".format(hex(pkg._flags))
    s += "{} ".format(pkg.function.name)
    s += "len:{} ".format(pkg.get_payload_size())

    if (pkg.type_ == MSPPacketType.RESPONSE):
        if (pkg.function == MSPTypes.MSP_ELRS_GET_BACKPACK_VERSION):
            s += "-- {}".format(pkg.payload.decode('utf-8'))

    elif (pkg.type_ == MSPPacketType.COMMAND):
        if (pkg.function == MSPTypes.MSP_ELRS_SET_SEND_UID):
            uuid = ','.join([str(int(i)) for i in pkg.payload][1:])
            s += "-- {}".format(str(uuid))

        elif (pkg.function == MSPTypes.MSP_ELRS_SET_OSD):
            if pkg.payload[0] == 0x04:
                s += "-- DISPLAY"
            elif pkg.payload[0] == 0x02:
                s += "-- CLEAR"
            elif pkg.payload[0] == 0x03:
                s += "-- SEND_TEXT({},{}): {}".format(
                            int(pkg.payload[2]),  # x position
                            int(pkg.payload[1]),  # y position
                            pkg.payload[4:].decode('utf-8')
                        )

    if ('--' not in s):
        s += "-- {}".format(pkg.payload.hex(" ", 2))

    return s


def log_msp_data(logger, data):
    for pkt in MSPPacket.packets_from_bytes(data):
        logger.debug(pkt2str(pkt))


def serial_to_tcp(ser: serial.Serial, sock: socket.socket):
    logger = create_logger("SER -> TCP")
    logger.debug("Start")
    try:
        while not stop_event.is_set():
            data = ser.read(1024)
            if data:
                try:
                    log_msp_data(logger, data)
                    sock.sendall(data)
                    logger.info(f"Relayed {len(data)} bytes")
                except socket.error as e:
                    logger.error(f"Socket send error: {e}")
                    break

    except serial.SerialException as e:
        logger.error(f"Serial port error: {e}")
    except Exception as e:
        if not stop_event.is_set():
            logger.error("Unexpected error: {}".format(e))
    finally:
        logger.debug("Thread stopping.")
        stop_event.set()


def tcp_to_serial(ser: serial.Serial, sock: socket.socket):
    logger = create_logger("TCP -> SER")
    logger.debug("Start")
    try:
        while not stop_event.is_set():
            try:
                data = sock.recv(1024)
                if not data:
                    logger.info("Client disconnected.")
                    break

                log_msp_data(logger, data)
                ser.write(data)
                logger.info(f"Relayed {len(data)} bytes")

            except socket.error as e:
                if not stop_event.is_set():
                    logger.error(f"Socket recv error: {e}")
                break

    except serial.SerialException as e:
        logger.error(f"Serial port write error: {e}")
    except Exception as e:
        if not stop_event.is_set():
            logger.error(f"Unexpected error: {e}")
    finally:
        logger.debug("Thread stopping.")
        stop_event.set()


def main():
    parser = argparse.ArgumentParser(
        description="RotorHazard Bridge -- used to bridge TCP <-> Serial for a ESP32 backpack timer module.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--device",
        default="/dev/ttyUSB0",
        help="Serial device path"
    )
    parser.add_argument(
        "--port",
        type=int,
        default="8080",
        help="TCP port to listen on"
    )
    args = parser.parse_args()

    logger = create_logger("MAIN")
    logger.info(f"Starting bridge on {args.device} <-> TCP 0.0.0.0:{args.port}")

    try:
        ser = serial.Serial(
            port=args.device,
            baudrate=460800,
            bytesize=serial.EIGHTBITS,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            xonxoff=False,
            rtscts=False,
            dsrdtr=False,
            timeout=0.1                # Read timeout in seconds
        )
        logger.debug(f"Successfully opened serial port {args.device}")
    except serial.SerialException as e:
        logger.error(f"Error: Could not open serial port {args.device}: {e}")
        sys.exit(1)

    try:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_REUSEADDR,
            1
        )
        server_sock.bind(('', args.port))
        server_sock.listen(1)
        logger.info(f"Listening on TCP port {args.port}...")

    except socket.error as e:
        logger.error(f"Error: Could not start TCP server on port {args.port}: {e}")
        ser.close()
        sys.exit(1)

    try:
        while True:
            try:
                client_sock, addr = server_sock.accept()
                logger.info(f"--- Incomming connection {addr} ---")
                client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                stop_event.clear()

                t1 = threading.Thread(
                    target=serial_to_tcp,
                    args=(ser, client_sock),
                    daemon=True
                )
                t2 = threading.Thread(
                    target=tcp_to_serial,
                    args=(ser, client_sock),
                    daemon=True
                )
                t1.start()
                t2.start()

                while t1.is_alive() and t2.is_alive():
                    time.sleep(0.1)
                logger.info(f"--- Client {addr} disconnected ---")
                client_sock.close()

            except socket.error as e:
                logger.error(f"Client connection error: {e}")
            except Exception as e:
                logger.error(f"An unexpected error occurred: {e}")

    except KeyboardInterrupt:
        logger.warning("Interrupted!!")
    finally:
        stop_event.set()
        if 'server_sock' in locals():
            server_sock.close()
            logger.debug("Server socket closed.")
        if ser.is_open:
            ser.close()
            logger.debug("Serial port closed.")
        logger.debug("Goodbye")


if __name__ == "__main__":
    main()
