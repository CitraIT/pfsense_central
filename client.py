#!/usr/local/bin/python3.8

import sys
import socket
import json
from select import select


LOCAL_ENDPOINT_ADDR = '127.0.0.1'
LOCAL_ENDPOINT_PORT = 8008
server_address = '192.168.0.175'
server_port = 9099

customer_data = {
        "api_key": "2267071a298e42f58c885d64df38647d",
        "customer": "citrait"
}


if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f'connecting to server on {server_address}:{server_port}')
    s.connect((server_address, server_port))
    print(f'connected! sending data...')
    s.sendall(json.dumps(customer_data).encode('utf-8'))
    print(f'data sent')
    received = s.recv(4096).decode()

    # closing actual socket, communication already set
    s.close()

    # parsing received data from server
    print(f'received: received')
    server_data = json.loads(received)
    print(f'authorization: {server_data["authorization"]}')
    if(server_data["authorization"]) == "ok":
            print(f'authorization ok.')
    else:
            print(f'authorization error! check with support!')
            sys.exit(2)

    # connecting to reverse proxy if we shall proceed
    reverse_proxy_port = int(server_data["proxy_port"])
    print(f'connecting with server {server_address} on reverse proxy port {reverse_proxy_port}')
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.connect((server_address, reverse_proxy_port))
    print(f'connected to reverse proxy. waiting for incoming requests!')

    readable_sockets = []
    writable_sockets = []
    exceptional_sockets = []

    while True:
            # receive data from user browser
            #readable_sockets.append(proxy_socket)

            user_data_binary = proxy_socket.recv(8192)
            user_data = user_data_binary.decode()
            user_request_headers = user_data.split('\r\n\t\n')[0].split('\r\n')
            if user_data.startswith('GET'):
                print(f'received GET request from proxy')
            elif user_data.startswith('POST'):
                print(f'received POST request')
            else:
                print(f'skipping unknow request...')
                continue

            print(f'request first line: {user_request_headers[0]}')

            # carrying user request to local webserver
            print(f'sending data to real firewall webserver')
            socket_firewall = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket_firewall.connect((LOCAL_ENDPOINT_ADDR, LOCAL_ENDPOINT_PORT))
            socket_firewall.sendall(user_data_binary)

            # read returned data from local webserver
            webserver_data_binary = socket_firewall.recv(8192)
            print(f'data received from local webserver')
            #webserver_data = webserver_data_binary.decode()
            response_headers = [ x.decode() for x in webserver_data_binary.split(b'\r\n\r\n')[0].split(b'\r\n') ]
            print(f'headers: {response_headers}')
            #ipdb.set_trace()
            #ipdb.pm()
            response_body_starts = webserver_data_binary.index(b'\r\n\r\n') + 4
            # response_body = webserver_data_binary.split(b'\r\n\r\n')[1] #.split(b'\r\n')[0]
            response_body = webserver_data_binary[response_body_starts:] #.split(b'\r\n')[0]
            
            response_headers_copy = response_headers.copy()
            response_headers_copy.pop(0)
            # print(f'--- RESPONSE HEADERS ----')
            # print(f'{response_headers_copy}')
            # print(f'--- RESPONSE BODY ----')
            #print(f'{response_body}')
            
            # send data back to user proxy.
            print(f'sending data back to proxy')
            proxy_socket.sendall(webserver_data_binary)
            
            # check headers
            for header_line in response_headers_copy:
                print(f'{header_line}')
                #header_name, header_value = header_line.split(': ')
                # blacklist headers
                blacklist_headers = ['date', 'last-modified', 'expires', 'set-cookie', 'location']
                found_blacklisted_header = False
                for b in blacklist_headers:
                    if header_line.lower().startswith(b):
                        found_blacklisted_header = True
                if found_blacklisted_header:
                    continue

                if ':' in header_line:
                    header_name, header_value = header_line.split(':')
                    header_name = header_name.strip()
                    header_value = header_value.strip()
                else:
                    print(f'skipping header {header_line}')
                    continue
                
                
                # check if content length is present
                if header_name == 'Content-Length':
                    print(f'content-length header is present.')
                    content_length = int(header_value)
                    bytes_received = len(response_body)
                    while bytes_received < content_length:
                        print(f'content-length: {content_length} bytes-received: {bytes_received}')
                        response_body = socket_firewall.recv(8192)
                        print(f'next chunk arrived. returning it data to proxy...')
                        proxy_socket.sendall(response_body)
                        bytes_received += len(response_body)
                # if no content length, is the webserver using chunks?
                elif header_name == 'Transfer-Encoding' and header_value == 'chunked':
                    print(f'detected chuncked transfer-encoding...')
                    # receive all chunks before send them
                    # check if more chunks:
                    while not response_body.endswith(b'\r\n\r\n'):
                        print(f'waiting next chunk...')
                        response_body = socket_firewall.recv(8192)
                        print(f'next chunk arrived. returning it data to proxy...')
                        proxy_socket.sendall(response_body)
                    print(f'final chunk sent!! we are freeeeee :)')

                    
            
            # close firewall connection:
            socket_firewall.close()




