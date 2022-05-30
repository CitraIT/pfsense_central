#-*- coding: utf8 -*-
# CitraIT - Excelência em TI
# App Prova de conceito para projeto: Central pfSense
# @Author: luciano@citrait.com.br
# @Date: 28/05/2022
#

from threading import Thread
import socket
import json
import random
from select import select
from queue import Queue
import ipdb

SOCKET_BIND_ADDR = '0.0.0.0'
SOCKET_BIND_PORT = 9099

api_keys = {'2267071a298e42f58c885d64df38647d': 'fw0001'}

available_ports = [x for x in range(40000, 45000, 1)]
print(f'available ports: {len(available_ports)}')


def start_new_proxy(customer, endpoint_remote_ip, listen_port, firewall_name):
    
    # setup proxy for firewall endpoint
    print(f'starting a new firewall proxy on port {listen_port} for:')
    print(f'customer: {customer}, firewall_ip: {endpoint_remote_ip}, firewall_name: {firewall_name}')
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.bind((SOCKET_BIND_ADDR, listen_port))
    proxy_socket.listen(100)
    print(f'waiting for proxy reverse connection from {endpoint_remote_ip}')
    firewall_endpoint, firewall_addr = proxy_socket.accept()
    #firewall_endpoint.setblocking(False)
    print(f'[proxy] successfully connected  from {endpoint_remote_ip}')
    # firewall_socket.sendall(b'successfully connected!')
    
    # at this point the firewall endpoint is connected.
    # now it's time to wait for user connection
    # setup proxy for user endpoint
    port = random.choice(available_ports)
    available_ports.remove(port)
    user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    user_socket.bind((SOCKET_BIND_ADDR, port))
    user_socket.listen(100)
    print(f'waiting for user connection on http://{SOCKET_BIND_ADDR}:{port}...')
    
    # loop requests    
    while True:
        user_endpoint, user_addr = user_socket.accept()
        #user_endpoint.setblocking(False)
        print(f'user connection received from: {user_addr[0]}:{user_addr[1]}')
        
        # parse http request from client browser
        user_data_binary = user_endpoint.recv(8192)
        user_data = user_data_binary.decode()
        user_request_headers = user_data.split("\r\n\r\n")[0].split("\r\n")
        if user_data.startswith("GET"):
            print(f'got GET request from user browser')
        elif user_data.startswith("POST"):
            print(f'got POST request from user browser')
        else:
            print(f'got UNKNOW request from user browser')
            user_endpoint.close()
            continue
        
        print(f'first line of requset: {user_request_headers[0]}')
            
        
        
        
        # sending received data to remote firewall
        print(f'sending all data direct to firewall proxy endpoint')
        firewall_endpoint.sendall(user_data_binary)
        print(f'data sent to remote firewall proxy endpoint')
        
        # read returned data from remote proxy
        print(f'waiting to receive data from remote proxy endpoint')
        firewall_data_binary = firewall_endpoint.recv(8192)
        print(f'received data from remote proxy endpoint')
        #webserver_data = webserver_data_binary.decode()
        response_headers = [ x.decode() for x in firewall_data_binary.split(b'\r\n\r\n')[0].split(b'\r\n') ]
        #ipdb.set_trace()
        #ipdb.pm()
        response_body_starts = firewall_data_binary.index(b'\r\n\r\n') + 4
        # response_body = firewall_data_binary.split(b'\r\n\r\n')[1] #.split(b'\r\n')[0]
        response_body = firewall_data_binary[response_body_starts:]
        response_headers_copy = response_headers.copy()
        response_headers_copy.pop(0)
        # print(f'--- RESPONSE HEADERS ----')
        # print(f'{response_headers_copy}')
        # print(f'--- RESPONSE BODY ----')
        #print(f'{response_body}')
        
        # send data to user...
        print(f'sending data back to user')
        user_endpoint.sendall(firewall_data_binary)
        
        
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
                continue
            
            
            # check if content length is present
            if header_name == 'Content-Length':
                print(f'content-length header is present.')
                content_length = int(header_value)
                bytes_received = len(response_body)
                while bytes_received < content_length:
                    print(f'waiting next chunk...')
                    response_body = firewall_endpoint.recv(8192)
                    print(f'next chunk arrived. returning it data to user...')
                    user_endpoint.sendall(response_body)
                    bytes_received += len(response_body)
                    print(f'content-length: {content_length}, received: {bytes_received}')
            # just one response or many?
            elif header_name == 'Transfer-Encoding' and header_value == 'chunked':
                print(f'detected chuncked transfer-encoding...')
                
                # receive all chunks before send them
                # check if more chunks:
                while not response_body.endswith(b'\r\n\r\n'):
                    print(f'not at final chunk.')
                    print(f'waiting next chunk...')
                    response_body = firewall_endpoint.recv(8192)
                    print(f'next chunk arrived. returning it data to user...')
                    user_endpoint.sendall(response_body)
                print(f'final chunk sent!! we are freeeeee :)')

        
        # closing user endpoint
        print(f'closing this socket, we served til the end.')
        user_endpoint.close()
        


    
    

if __name__ == '__main__':
    print(f'inicializando app...')
    main_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    main_socket.bind((SOCKET_BIND_ADDR, SOCKET_BIND_PORT))
    main_socket.listen(100)
    while True:
        # waiting for next connection from a firewall
        print(f'aguardando conexao...')
        endpoint_socket, client_addr = main_socket.accept()
        print(f'received connection from {client_addr[0]}:{client_addr[1]}')
        
        # reading data from connection: api_key, customer_name
        received = endpoint_socket.recv(4096).decode()
        customer_data = json.loads(received)
        print(f'customer api key: {customer_data["api_key"]}')
        customer_firewall = api_keys.get(customer_data['api_key'])
        print(f'incoming firewall: {customer_firewall}')
        print(f'generating available port...')
        
        # allocate a new proxy port for this incoming firewall
        port = random.choice(available_ports)
        available_ports.remove(port)
        response_data = {'authorization': 'ok', 'proxy_port': port}
        
        # starting the proxy socket
        print(f'iniciando thread proxy na porta {port}')
        t = Thread(target=start_new_proxy, args=(customer_data["customer"], client_addr[0], port, customer_firewall), daemon=True)
        t.start()
        print(f'thread inicializada com id: {t.name}')
        
        # telling the remote firewall to connect to reverse proxy on another port
        print(f'informando ao firewall remoto para conectar no proxy reverso na porta: {port}')
        endpoint_socket.sendall(json.dumps(response_data).encode('utf-8'))
        endpoint_socket.close()
