from socket import socket, AF_PACKET, SOCK_RAW, ntohs
import struct
import sys
import random
import time


class socketPPP:
    def __init__(self, payload=None, flag=None, addr=None, FCS=None, control=None, protocol=None, escape=None,
                 val_ale=None, name=None):
        self.addr = addr
        self.flag = flag
        self.control = control
        self.payload = payload          # Mensaje a enviar
        self.FCS = FCS                  # CRC
        self.protocol = protocol
        self.escape = escape
        self.val_ale = val_ale
        self.name = name

    @staticmethod
    def hex_to_bin(cadena_hex):
        n = int(cadena_hex, 16)
        cadena_bin = ''
        while n > 0:
            cadena_bin = str(n % 2) + cadena_bin
            n = n >> 1
        return cadena_bin

    @staticmethod
    def bin_to_dec(n):
        return int(n, 2)

    @staticmethod
    def str_bin(n):
        binary_converted_pass = ''.join(format(ord(c), 'b') for c in n)
        return binary_converted_pass

    @staticmethod
    def decimalToBinary(n):
        return bin(n).replace("0b", "")

    def byte_stuff(self, datos):
        ret = []
        c = 0
        j = ""
        for i in range(int(len(datos) / 8)):
            if datos[c:c + 8] == self.flag or datos[c:c + 8] == self.escape:
                ret.append(self.escape)
                ret.append(datos[c:c + 8])
                c += 8
            else:
                ret.append(datos[c:c + 8])
                c += 8
        for i in range(len(ret)):
            j += ret[i]
        return j

    def byte_unstuff(self, datos):
        retUS = []
        c = 0
        j = ""
        k = 0
        while c < (len(datos) / 8):
            if datos[k: k + 8] == self.escape:
                c += 1
                k += 8
            retUS.append(datos[k:k + 8])
            c += 1
            k += 8
        for i in range(len(retUS)):
            j += retUS[i]
        return j

    @staticmethod
    def xor(crc, tmp):  # Iguales son 0, diferentes 1
        result = []
        for i in range(0, len(tmp)):
            if crc[i] == tmp[i]:
                result.append('0')
            else:
                result.append('1')
        return ''.join(result)

    def mod2div_tx(self, mensaje=None, polinomio_crc="100000100100000010000110110110101"):
        cont_pos_send = 0  # Cuenta la pos. del men. en la que se encuentra
        acu_zeros = 0  # Cuantos ceros se quitan
        avance_analisis = 0  # Ayuda a posicionar al contador de posicion
        tamanio_checksum = len(polinomio_crc) - 1  # CRC-32
        mensaje_crc = mensaje + "0" * tamanio_checksum  # Se suman zeros
        tmp = mensaje_crc[0: tamanio_checksum]
        for i in range(len(mensaje_crc) - 1):  # Ciclo for comienza en cero
            while cont_pos_send < len(mensaje_crc):
                if tmp[0] == '1':
                    tmp = self.xor(polinomio_crc, tmp)
                else:
                    for j in range(len(polinomio_crc) - 2):
                        if tmp[j] == '0' and acu_zeros < len(tmp):
                            acu_zeros += 1
                        else:
                            relleno = mensaje_crc[len(tmp) + avance_analisis:len(tmp) + avance_analisis + acu_zeros]
                            avance_analisis += acu_zeros
                            tmp = tmp[acu_zeros:len(tmp)] + relleno
                            acu_zeros = 0
                            cont_pos_send = len(tmp) + avance_analisis
                            break
            break
        if len(tmp) == len(polinomio_crc) - 1:  # Se comprueba el tamanio del pol_res 32 bits
            return tmp
        elif len(tmp) > len(polinomio_crc) - 1:  # Mayor tamaño pol_res ajuste
            tmp = tmp[len(tmp) - len(polinomio_crc) - 1:len(tmp)]
            return tmp
        else:  # Menor tamaño pol_res ajuste
            tmp = "0" * (len(polinomio_crc) - 1 - len(tmp)) + tmp
            return tmp

    def mod2div_rx(self, mensaje=None, polinomio_crc_tx=None, polinomio_crc=None):
        cont_pos_send = 0
        acu_zeros = 0
        avance_analisis = 0
        tamanio_checksum = len(polinomio_crc) - 1
        mensaje_crc = mensaje + polinomio_crc_tx  # Se suma el pol_crc_tx
        tmp = mensaje_crc[0: tamanio_checksum]
        for i in range(len(mensaje_crc) - 1):
            while avance_analisis < len(mensaje_crc):
                if tmp[0] == '1':
                    tmp = self.xor(polinomio_crc, tmp)
                else:
                    for j in range(len(polinomio_crc) - 2):
                        if tmp[j] == '0' and cont_pos_send < len(tmp):
                            cont_pos_send += 1
                        else:
                            relleno = mensaje_crc[len(tmp) + acu_zeros:len(tmp) + acu_zeros + cont_pos_send]
                            acu_zeros += cont_pos_send
                            tmp = tmp[cont_pos_send:len(tmp)] + relleno
                            cont_pos_send = 0
                            avance_analisis = len(tmp) + acu_zeros
                            break
            break
        if len(tmp) == (len(polinomio_crc) - 1):
            return tmp
        elif len(tmp) > (len(polinomio_crc) - 1):
            tmp = tmp[len(tmp) - len(polinomio_crc) - 1:len(tmp)]
            return tmp
        else:
            tmp = "0" * (len(polinomio_crc) - 1 - len(tmp)) + tmp
            return tmp

    @staticmethod
    def enviar(lcp=None):
        socketRawTx = socket(AF_PACKET, SOCK_RAW)
        socketRawTx.bind(("enp59s0", 0))
        socketRawTx.send(lcp)
        socketRawTx.close()

    @staticmethod
    def recibir():
        socketRawRx = socket(AF_PACKET, SOCK_RAW, ntohs(3))
        socketRawRx.bind(('enp59s0', 0))
        frame = socketRawRx.recvfrom(2048)
        socketRawRx.close()
        return frame

    def frameLCP_configure_request_tx(self):
        self.escape = "01111101"

        self.flag = "01111110"
        flag_dec = self.bin_to_dec(self.flag)

        self.addr = "11111111"
        addr_dec = self.bin_to_dec(self.addr)

        self.control = "00000011"
        control_dec = self.bin_to_dec(self.control)

        protocol_hex_in = "C021"
        self.protocol = self.hex_to_bin(protocol_hex_in)
        protocol_dec = self.bin_to_dec(self.protocol)

        payload_code_bin = "00000001"
        payload_code_bin_stuff = self.byte_stuff(payload_code_bin)

        payload_id_dec = random.randint(0, 256)
        payload_id_bin = self.decimalToBinary(payload_id_dec)
        if len(payload_id_bin) < 8:
            payload_id_bin = "0" * (8 - len(payload_id_bin)) + payload_id_bin
        # payload_id_bin = "00001000"
        payload_id_bin_stuff = self.byte_stuff(payload_id_bin)

        payload_info_bin = "01111110011111100111111001111110"
        payload_info_bin_stuff = self.byte_stuff(payload_info_bin)

        payload_length_dec = int(len(payload_info_bin) / 8)
        payload_length_bin_incomplete = self.decimalToBinary(payload_length_dec)
        payload_length_bin = "0" * (16 - len(payload_length_bin_incomplete)) + payload_length_bin_incomplete
        payload_length_bin_stuff = self.byte_stuff(payload_length_bin)

        self.payload = payload_code_bin_stuff + payload_id_bin_stuff + payload_length_bin_stuff + payload_info_bin_stuff

        lcp_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.byte_stuff(self.mod2div_tx(mensaje=lcp_bin_sin_fcs))
        fcs_dec = self.bin_to_dec(self.FCS)

        lcp_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        lcp_hex_dos = lcp_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

        # print(lcp_hex_dos)
        time.sleep(2)
        self.enviar(lcp_hex_dos)

        self.frameLCP_configure_ack_rx()

    def frameLCP_configure_ack_rx(self):
        # conf_ack_rx = b'~\xff\x03\xc0!000000100000100000000000000001000111110101111110011111010111111001111101011111100111110101111110\x00\x00\x00\x00\x14\xca\xe40~'
        
        conf_ack_rx_tupla = self.recibir()
        conf_ack_rx = conf_ack_rx_tupla[0]

        conf_ack_flag_dec = conf_ack_rx[0]
        self.flag = self.decimalToBinary(conf_ack_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        conf_ack_addr_dec = conf_ack_rx[1]
        self.addr = self.decimalToBinary(conf_ack_addr_dec)

        conf_ack_control_dec = conf_ack_rx[2]
        self.control = self.decimalToBinary(conf_ack_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        conf_ack_protocol = struct.unpack("!H", conf_ack_rx[3:5])
        self.protocol = self.decimalToBinary(conf_ack_protocol[0])

        conf_ack_payload_bin = conf_ack_rx[5:len(conf_ack_rx) - 9].decode("utf-8")
        self.payload = conf_ack_payload_bin

        conf_ack_fcs = struct.unpack("!Q", conf_ack_rx[len(conf_ack_rx) - 9:len(conf_ack_rx) - 1])
        conf_ack_fcs_dec = conf_ack_fcs[0]
        conf_ack_fcs_bin = self.decimalToBinary(conf_ack_fcs_dec)
        if len(conf_ack_fcs_bin) < 32:
            conf_ack_fcs_bin = "0" * (32 - len(conf_ack_fcs_bin)) + conf_ack_fcs_bin
        self.FCS = self.byte_unstuff(conf_ack_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            self.frameCHAP_challenge_rx()

        else:
            print("Datos recibidos con errores")
            print("Conexión finalizada")
            sys.exit()              # Estado dead

    def frameCHAP_challenge_rx(self):
        # chap_challenge_rx = b'~\xff\x03\xc2#0000000100000101000000000000011000000010000000000000101000001001001111001111000011100011\x00\x00\x00\x00\xd1\x12\x01\xb8~'
        chap_challenge_rx_tupla = self.recibir()
        chap_challenge_rx = chap_challenge_rx_tupla[0]

        challenge_flag_dec = chap_challenge_rx[0]
        self.flag = self.decimalToBinary(challenge_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        challenge_addr_dec = chap_challenge_rx[1]
        self.addr = self.decimalToBinary(challenge_addr_dec)

        challenge_control_dec = chap_challenge_rx[2]
        self.control = self.decimalToBinary(challenge_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        challenge_protocol = struct.unpack("!H", chap_challenge_rx[3:5])
        self.protocol = self.decimalToBinary(challenge_protocol[0])

        challenge_payload_bin = chap_challenge_rx[5:len(chap_challenge_rx) - 9].decode("utf-8")
        self.payload = challenge_payload_bin

        challenge_fcs = struct.unpack("!Q", chap_challenge_rx[len(chap_challenge_rx) - 9:len(chap_challenge_rx) - 1])
        challenge_fcs_dec = challenge_fcs[0]
        challenge_fcs_bin = self.decimalToBinary(challenge_fcs_dec)
        if len(challenge_fcs_bin) < 32:
            challenge_fcs_bin = "0" * (32 - len(challenge_fcs_bin)) + challenge_fcs_bin
        self.FCS = self.byte_unstuff(challenge_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            self.frameCHAP_response_tx()
        else:
            print("Datos recibidos con errores")
            print("Conexión finalizada")
            sys.exit()  # Estado dead

    def frameCHAP_response_tx(self):
        flag_dec = self.bin_to_dec(self.flag)

        addr_dec = self.bin_to_dec(self.addr)

        control_dec = self.bin_to_dec(self.control)

        protocol_dec = self.bin_to_dec(self.protocol)

        payload_code = "00000010"

        usuario_str = input("Ingresa su nombre: ")
        self.name = usuario_str
        usuario_bin = self.str_bin(usuario_str)
        lon_usuario = int(len(usuario_str) * 8)
        if len(usuario_bin) < lon_usuario:
            usuario_bin = "0" * (lon_usuario - len(usuario_bin)) + usuario_bin

        password_str = input("Ingrese su contraseña: ")
        password_bin = self.str_bin(password_str)

        lon_val_ale = self.bin_to_dec(self.payload[32:40])
        val_ale_dec = self.bin_to_dec(self.payload[40:40 + (lon_val_ale * 8)])
        val_ale_bin = self.decimalToBinary(val_ale_dec)
        if len(val_ale_bin) < 16:
            val_ale_bin = "0" * (16 - len(val_ale_bin)) + val_ale_bin

        mensaje_bin = password_bin + val_ale_bin
        payload_response_value = self.mod2div_tx(mensaje_bin)

        payload_response_length_dec = int(len(payload_response_value) / 8)
        payload_response_length_bin = self.decimalToBinary(payload_response_length_dec)
        if len(payload_response_length_bin) < 8:
            payload_response_length_bin = "0" * (8 - len(payload_response_length_bin)) + payload_response_length_bin

        payload_length_dec = int((len(payload_response_value) + len(usuario_bin)) / 8)
        payload_length_bin = self.decimalToBinary(payload_length_dec)
        if len(payload_length_bin) < 16:
            payload_length_bin = "0" * (16 - len(payload_length_bin)) + payload_length_bin

        self.payload = payload_code + self.payload[8:16] + payload_length_bin + payload_response_length_bin + payload_response_value + usuario_bin
        self.payload = self.byte_stuff(self.payload)

        response_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.mod2div_tx(mensaje=response_bin_sin_fcs)
        fcs_dec = self.bin_to_dec(self.byte_stuff(self.FCS))

        response_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        response_hex_dos = response_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

        # print(response_hex_dos)
        time.sleep(2)
        self.enviar(response_hex_dos)

        self.frameCHAP_succes_failure_rx()

    def frameCHAP_succes_failure_rx(self):
        # succes_failure_rx = b'~\xff\x03\xc2#0000001100000101000000000000011100000001010011111010111000111100011110010111100111110011\x00\x00\x00\x00\xf4\xac\xc6$~'
        succes_failure_rx_tupla = self.recibir()
        succes_failure_rx = succes_failure_rx_tupla[0]

        success_failure_flag_dec = succes_failure_rx[0]
        self.flag = self.decimalToBinary(success_failure_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        success_failure_addr_dec = succes_failure_rx[1]
        self.addr = self.decimalToBinary(success_failure_addr_dec)

        success_failure_control_dec = succes_failure_rx[2]
        self.control = self.decimalToBinary(success_failure_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        success_failure_protocol = struct.unpack("!H", succes_failure_rx[3:5])
        self.protocol = self.decimalToBinary(success_failure_protocol[0])

        success_failure_payload_bin = succes_failure_rx[5:len(succes_failure_rx) - 9].decode("utf-8")
        self.payload = success_failure_payload_bin

        success_failure_fcs = struct.unpack("!Q", succes_failure_rx[len(succes_failure_rx) - 9:len(succes_failure_rx) - 1])
        success_failure_fcs_dec = success_failure_fcs[0]
        success_failure_fcs_bin = self.decimalToBinary(success_failure_fcs_dec)
        if len(success_failure_fcs_bin) < 32:
            success_failure_fcs_bin = "0" * (32 - len(success_failure_fcs_bin)) + success_failure_fcs_bin
        self.FCS = self.byte_unstuff(success_failure_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            self.frameIPCP_configure_request_tx()
        else:
            print("Datos recibidos con errores")
            print("Conexión finalizada")
            sys.exit()  # Estado dead

    def frameIPCP_configure_request_tx(self):
        if self.payload[0:8] == "00000011":
            flag_dec = self.bin_to_dec(self.flag)

            addr_dec = self.bin_to_dec(self.addr)

            control_dec = self.bin_to_dec(self.control)

            protocol_hex_in = "8021"
            self.protocol = self.hex_to_bin(protocol_hex_in)
            protocol_dec = self.bin_to_dec(self.protocol)

            payload_code_bin = "00000001"
            payload_code_bin_stuff = self.byte_stuff(payload_code_bin)

            payload_id_dec = random.randint(0, 256)
            payload_id_bin = self.decimalToBinary(payload_id_dec)
            if len(payload_id_bin) < 8:
                payload_id_bin = "0" * (8 - len(payload_id_bin)) + payload_id_bin
            # payload_id_bin = "00001000"
            payload_id_bin_stuff = self.byte_stuff(payload_id_bin)

            payload_info_bin = "01111110011111100111111001111110"
            payload_info_bin_stuff = self.byte_stuff(payload_info_bin)

            payload_length_dec = int(len(payload_info_bin) / 8)
            payload_length_bin_incomplete = self.decimalToBinary(payload_length_dec)
            payload_length_bin = "0" * (16 - len(payload_length_bin_incomplete)) + payload_length_bin_incomplete
            payload_length_bin_stuff = self.byte_stuff(payload_length_bin)

            self.payload = payload_code_bin_stuff + payload_id_bin_stuff + payload_length_bin_stuff + payload_info_bin_stuff

            ipcp_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
            self.FCS = self.byte_stuff(self.mod2div_tx(mensaje=ipcp_bin_sin_fcs))
            fcs_dec = self.bin_to_dec(self.FCS)

            ipcp_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
            ipcp_hex_dos = ipcp_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

            # print(ipcp_hex_dos)
            time.sleep(2)
            self.enviar(ipcp_hex_dos)

            self.frameIPCP_configure_ack_rx()
        else:
            self.frameLCP_terminate_request_tx()

    def frameIPCP_configure_ack_rx(self):
        # conf_ack_rx = b'~\xff\x03\x80!000000100000100000000000000001000111110101111110011111010111111001111101011111100111110101111110\x00\x00\x00\x00.\xa8n\x04~'
        conf_ack_rx_tupla = self.recibir()
        conf_ack_rx = conf_ack_rx_tupla[0]

        conf_ack_flag_dec = conf_ack_rx[0]
        self.flag = self.decimalToBinary(conf_ack_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        conf_ack_addr_dec = conf_ack_rx[1]
        self.addr = self.decimalToBinary(conf_ack_addr_dec)

        conf_ack_control_dec = conf_ack_rx[2]
        self.control = self.decimalToBinary(conf_ack_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        conf_ack_protocol = struct.unpack("!H", conf_ack_rx[3:5])
        self.protocol = self.decimalToBinary(conf_ack_protocol[0])

        conf_ack_payload_bin = conf_ack_rx[5:len(conf_ack_rx) - 9].decode("utf-8")
        self.payload = conf_ack_payload_bin

        conf_ack_fcs = struct.unpack("!Q", conf_ack_rx[len(conf_ack_rx) - 9:len(conf_ack_rx) - 1])
        conf_ack_fcs_dec = conf_ack_fcs[0]
        conf_ack_fcs_bin = self.decimalToBinary(conf_ack_fcs_dec)
        if len(conf_ack_fcs_bin) < 32:
            conf_ack_fcs_bin = "0" * (32 - len(conf_ack_fcs_bin)) + conf_ack_fcs_bin
        self.FCS = self.byte_unstuff(conf_ack_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            self.data_transfer_user()
        else:
            print("Datos recibidos con errores")
            sys.exit()                  # Estado dead

    def frameIP_tx(self):
        flag_dec = self.bin_to_dec(self.flag)

        addr_dec = self.bin_to_dec(self.addr)

        control_dec = self.bin_to_dec(self.control)

        protocol_hex_in = "0021"
        self.protocol = self.hex_to_bin(protocol_hex_in)
        if len(self.protocol) < 16:
            self.protocol = "0" * (16 - len(self.protocol)) + self.protocol
        protocol_dec = self.bin_to_dec(self.protocol)

        print("Usuario ", self.name, ": ")

        payload_user_data_str_input = input()
        payload_user_data_str = payload_user_data_str_input
        payload_user_data_bin = self.str_bin(payload_user_data_str)
        lon_payload = len(payload_user_data_str) * 8
        if len(payload_user_data_bin) < lon_payload:
            payload_user_data_bin = "0" * (lon_payload - len(payload_user_data_bin)) + payload_user_data_bin
        payload_user_data_str = payload_user_data_str.encode("utf-8")

        self.payload = self.byte_stuff(payload_user_data_bin)

        ip_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.byte_stuff(self.mod2div_tx(mensaje=ip_bin_sin_fcs))
        fcs_dec = self.bin_to_dec(self.FCS)

        ip_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        ip_hex_dos = ip_hex_uno + payload_user_data_str + struct.pack("!QB", fcs_dec, flag_dec)

        # print(ip_hex_dos)
        time.sleep(2)
        self.enviar(ip_hex_dos)

        if payload_user_data_str_input == "adios" or payload_user_data_str_input == "Adios" or payload_user_data_str_input == "ADIOS":
            self.frameLCP_terminate_request_tx()
        else:
            self.frameIP_rx()

    def frameIP_rx(self):
        # ip_rx = b'~\xff\x03\x00!Hola\x00\x00\x00\x00/\x84+(~'
        ip_rx_tupla = self.recibir()
        ip_rx = ip_rx_tupla[0]

        ip_flag_dec = ip_rx[0]
        self.flag = self.decimalToBinary(ip_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        ip_addr_dec = ip_rx[1]
        self.addr = self.decimalToBinary(ip_addr_dec)

        ip_control_dec = ip_rx[2]
        self.control = self.decimalToBinary(ip_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        ip_protocol = struct.unpack("!H", ip_rx[3:5])
        self.protocol = self.decimalToBinary(ip_protocol[0])
        if len(self.protocol) < 16:
            self.protocol = "0" * (16 - len(self.protocol)) + self.protocol

        ip_payload = ip_rx[5:len(ip_rx) - 9].decode("utf-8")
        self.payload = self.str_bin(ip_payload)
        lon_payload = len(ip_payload) * 8
        if len(self.payload) < lon_payload:
            self.payload = "0" * (lon_payload - len(self.payload)) + self.payload

        ip_fcs = struct.unpack("!Q", ip_rx[len(ip_rx) - 9:len(ip_rx) - 1])
        ip_fcs_dec = ip_fcs[0]
        ip_fcs_bin = self.decimalToBinary(ip_fcs_dec)
        if len(ip_fcs_bin) < 32:
            ip_fcs_bin = "0" * (32 - len(ip_fcs_bin)) + ip_fcs_bin
        self.FCS = self.byte_unstuff(ip_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            print("Server : ")
            print(ip_payload)
            self.frameIP_tx()
        else:
            print("Datos recibidos con errores")
            self.frameLCP_terminate_request_tx()

    def data_transfer_user(self):
        print("Conectado con exito")
        self.frameIP_tx()

    def frameLCP_terminate_request_tx(self):
        flag_dec = self.bin_to_dec(self.flag)

        addr_dec = self.bin_to_dec(self.addr)

        control_dec = self.bin_to_dec(self.control)

        protocol_hex_in = "C021"
        self.protocol = self.hex_to_bin(protocol_hex_in)
        protocol_dec = self.bin_to_dec(self.protocol)

        payload_code = "00000101"

        payload_id_dec = random.randint(0, 256)
        payload_id_bin = self.decimalToBinary(payload_id_dec)
        if len(payload_id_bin) < 8:
            payload_id_bin = "0" * (8 - len(payload_id_bin)) + payload_id_bin
        # payload_id = "00001001"#duda

        # payload_info = "10000010010000001000011011011010"
        payload_info = "01111110011111100111111001111110"

        payload_length = int(len(payload_info) / 8)
        payload_length_bin_incomplete = self.decimalToBinary(payload_length)
        payload_length_bin = "0" * (16 - len(payload_length_bin_incomplete)) + payload_length_bin_incomplete

        self.payload = payload_code + payload_id_bin + payload_length_bin + payload_info
        self.payload = self.byte_stuff(self.payload)

        lcp_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.mod2div_tx(mensaje=lcp_bin_sin_fcs)
        fcs_dec = self.bin_to_dec(self.byte_stuff(self.FCS))

        terminate_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        terminate_hex_dos = terminate_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

        # print(terminate_hex_dos)
        time.sleep(2)
        self.enviar(terminate_hex_dos)

        self.frameLCP_terminate_ack_rx()

    def frameLCP_terminate_ack_rx(self):
        # terminate_ack_rx = b'~\xff\x03\xc0!000001100000100100000000000001000111110101111110011111010111111001111101011111100111110101111110\x00\x00\x00\x00\xc5\x816\xb4~'
        terminate_ack_rx_tupla = self.recibir()
        terminate_ack_rx = terminate_ack_rx_tupla[0]

        term_ack_flag_dec = terminate_ack_rx[0]
        self.flag = self.decimalToBinary(term_ack_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        term_ack_addr_dec = terminate_ack_rx[1]
        self.addr = self.decimalToBinary(term_ack_addr_dec)

        term_ack_control_dec = terminate_ack_rx[2]
        self.control = self.decimalToBinary(term_ack_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        term_ack_protocol = struct.unpack("!H", terminate_ack_rx[3:5])
        self.protocol = self.decimalToBinary(term_ack_protocol[0])

        term_ack_payload_bin = terminate_ack_rx[5:len(terminate_ack_rx) - 9].decode("utf-8")
        self.payload = term_ack_payload_bin

        term_ack_fcs = struct.unpack("!Q", terminate_ack_rx[len(terminate_ack_rx) - 9:len(terminate_ack_rx) - 1])
        term_ack_fcs_dec = term_ack_fcs[0]
        term_ack_fcs_bin = self.decimalToBinary(term_ack_fcs_dec)
        if len(term_ack_fcs_bin) < 32:
            term_ack_fcs_bin = "0" * (32 - len(term_ack_fcs_bin)) + term_ack_fcs_bin
        self.FCS = self.byte_unstuff(term_ack_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            print("Conexión Finalizada")
            sys.exit()              # Estado dead
        else:
            print("Datos recibidos con errores")
            sys.exit()              # Estado dead


def main():
    framePPP = socketPPP()
    framePPP.frameLCP_configure_request_tx()


main()
