#!/usr/bin/env python3

import argparse
import sys

import colorama
from colorama import Fore, Style

import sslyze
from sslyze import ScanCommandAttemptStatusEnum

colorama.init(autoreset=True)

# Protocol name, scan_result attribute name, deprecated flag
PROTOCOL_CHECKS = [
    ('SSL 2.0', 'ssl_2_0_cipher_suites', True),
    ('SSL 3.0', 'ssl_3_0_cipher_suites', True),
    ('TLS 1.0', 'tls_1_0_cipher_suites', True),
    ('TLS 1.1', 'tls_1_1_cipher_suites', True),
    ('TLS 1.2', 'tls_1_2_cipher_suites', False),
    ('TLS 1.3', 'tls_1_3_cipher_suites', False),
]


def _colored(text: str, color: str, bold: bool = False) -> str:
    prefix = Style.BRIGHT if bold else ''
    return f'{prefix}{color}{text}{Style.RESET_ALL}'


def _format_cipher(cipher_suite) -> str:
    """
    Returns a colored, formatted string for a cipher suite based on its security properties.

    Magenta = CBC without PFS (worst)
    Yellow  = CBC with PFS
    Blue    = no CBC but missing PFS
    Default = no issues flagged
    """
    name = cipher_suite.cipher_suite.name
    has_cbc = 'CBC' in str(cipher_suite)
    has_dhe = 'DHE' in str(cipher_suite)

    if has_cbc and not has_dhe:
        return f'\t- {_colored(name, Fore.MAGENTA)}'
    elif has_cbc:
        return f'\t- {_colored(name, Fore.YELLOW)}'
    elif not has_dhe:
        return f'\t- {_colored(name, Fore.BLUE)}'
    return f'\t- {name}'


def scan_target(target: str, port: int) -> list:
    """
    Scans a target for accepted cipher suites using sslyze.

    Args:
        target (str): The hostname or IP address of the target.
        port (int): The port number to connect to.

    Returns:
        list: A list of formatted strings representing the accepted ciphers.
    """
    try:
        server_scan_req = sslyze.ServerScanRequest(
            server_location=sslyze.ServerNetworkLocation(hostname=target, port=port),
            scan_commands={
                sslyze.ScanCommand.CERTIFICATE_INFO,
                sslyze.ScanCommand.SSL_2_0_CIPHER_SUITES,
                sslyze.ScanCommand.SSL_3_0_CIPHER_SUITES,
                sslyze.ScanCommand.TLS_1_0_CIPHER_SUITES,
                sslyze.ScanCommand.TLS_1_1_CIPHER_SUITES,
                sslyze.ScanCommand.TLS_1_2_CIPHER_SUITES,
                sslyze.ScanCommand.TLS_1_3_CIPHER_SUITES,
                sslyze.ScanCommand.HEARTBLEED,
                sslyze.ScanCommand.ROBOT,
                sslyze.ScanCommand.SESSION_RENEGOTIATION,
                sslyze.ScanCommand.HTTP_HEADERS,
            },
        )
    except sslyze.ServerHostnameCouldNotBeResolved:
        print("Error resolving the supplied hostname")
        return []

    scanner = sslyze.Scanner()
    scanner.queue_scans([server_scan_req])

    accepted_ciphers = []

    for server_scan_result in scanner.get_results():
        if server_scan_result.scan_status == sslyze.ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            print("The target could not be contacted")
            continue

        for protocol_name, attr_name, is_deprecated in PROTOCOL_CHECKS:
            attempt = getattr(server_scan_result.scan_result, attr_name)

            if attempt.status == ScanCommandAttemptStatusEnum.ERROR:
                continue

            if attempt.result is None:
                continue

            ciphers = attempt.result.accepted_cipher_suites
            if not ciphers:
                continue

            label = _colored(protocol_name, Fore.RED) if is_deprecated else protocol_name
            accepted_ciphers.append(f'\nAccepted Ciphers for {label}:')

            for cipher_suite in ciphers:
                name = cipher_suite.cipher_suite.name
                # SSL 2.0 and SSL 3.0 are categorically broken (DROWN, POODLE) —
                # individual cipher properties are irrelevant; show all in red.
                if protocol_name in ('SSL 2.0', 'SSL 3.0'):
                    accepted_ciphers.append(f'\t- {_colored(name, Fore.RED)}')
                # TLS 1.3 only uses AEAD ciphers — no need for colour coding
                elif protocol_name == 'TLS 1.3':
                    accepted_ciphers.append(f'\t- {name}')
                else:
                    accepted_ciphers.append(_format_cipher(cipher_suite))

    return accepted_ciphers


def main():
    """
    Main entry point for the cipherchecks tool.
    Parses command line arguments and initiates the scan.
    """
    sys.tracebacklimit = 0

    parser = argparse.ArgumentParser(
        prog='cipherchk',
        description='Check accepted TLS/SSL cipher suites for a target host',
    )
    parser.add_argument('target', nargs='?', help='Hostname or IP address of the target')
    parser.add_argument('port', nargs='?', type=int, help='Port number to connect to')
    args = parser.parse_args()

    target = args.target
    port = args.port

    try:
        if not target:
            target = input('[+] target: ')
        if not port:
            port = int(input('[+] port: '))
    except KeyboardInterrupt:
        sys.exit(0)

    print(f'[+] Checking Accepted Cipher Suites for: {_colored(target, Fore.GREEN)}')
    print((
        '\n'
        'Deprecated protocols are shown in {}\n'
        'CBC ciphers without PFS are shown in {}\n'
        'CBC ciphers are shown in {}\n'
        'Ciphers missing PFS are shown in {}'
    ).format(
        _colored('red', Fore.RED, bold=True),
        _colored('magenta', Fore.MAGENTA, bold=True),
        _colored('yellow', Fore.YELLOW, bold=True),
        _colored('blue', Fore.BLUE, bold=True),
    ))

    for cipher in scan_target(target, port):
        print(cipher)


if __name__ == '__main__':
    main()
