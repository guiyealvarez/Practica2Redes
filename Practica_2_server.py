import time
import random
import struct
from socket import socket, AF_PACKET, SOCK_RAW, ntohs


class socketPPP:
    def __init__(self, payload=None, flag=None, addr=None, FCS=None, control=None, protocol=None,
                 escape="01111101", name="Isac", password="TICS", vab_ale=None, crc_chap=None):
        self.addr = addr
        self.flag = flag
        self.control = control
        self.payload = payload      # Mensaje a enviar
        self.FCS = FCS              # CRC
        self.protocol = protocol
        self.escape = escape
        self.name = name
        self.password = password
        self.val_ale = vab_ale      # response Value
        self.crc_chap = crc_chap

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

    @staticmethod
    def decimalToBinary(n):
        return bin(n).replace("0b", "")

    @staticmethod
    def recibir():
        socketRawRx = socket(AF_PACKET, SOCK_RAW, ntohs(3))
        socketRawRx.bind(('enxf8e43ba33083', 0))
        frame = socketRawRx.recvfrom(2048)
        socketRawRx.close()
        return frame

    @staticmethod
    def enviar(lcp=None):
        socketRawTx = socket(AF_PACKET, SOCK_RAW)
        socketRawTx.bind(("enxf8e43ba33083", 0))
        socketRawTx.send(lcp)
        socketRawTx.close()

    def frameLCP_configure_request_rx(self):
        # conf_req_rx = b'~\xff\x03\xc0!000000010000100000000000000001000111110101111110011111010111111001111101011111100111110101111110\x00\x00\x00\x00\xf1\xb5\x9a\xc0~'
        conf_req_rx_tupla = self.recibir()
        conf_req_rx = conf_req_rx_tupla[0]

        conf_req_flag_dec = conf_req_rx[0]
        self.flag = self.decimalToBinary(conf_req_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        conf_req_addr_dec = conf_req_rx[1]
        self.addr = self.decimalToBinary(conf_req_addr_dec)

        conf_req_control_dec = conf_req_rx[2]
        self.control = self.decimalToBinary(conf_req_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        conf_req_protocol = struct.unpack("!H", conf_req_rx[3:5])
        self.protocol = self.decimalToBinary(conf_req_protocol[0])

        conf_req_payload_bin = conf_req_rx[5:len(conf_req_rx)-9].decode("utf-8")
        self.payload = conf_req_payload_bin

        conf_req_fcs = struct.unpack("!Q", conf_req_rx[len(conf_req_rx)-9:len(conf_req_rx)-1])
        conf_req_fcs_dec = conf_req_fcs[0]
        conf_req_fcs_bin = self.decimalToBinary(conf_req_fcs_dec)
        if len(conf_req_fcs_bin) < 32:
            conf_req_fcs_bin = "0" * (32 - len(conf_req_fcs_bin)) + conf_req_fcs_bin
        self.FCS = self.byte_unstuff(conf_req_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            self.frameLCP_configure_ack_tx()
        else:
            print("Datos recibidos con errores")
            self.frameLCP_configure_request_rx()

    def frameLCP_configure_ack_tx(self):
        flag_dec = self.bin_to_dec(self.flag)

        addr_dec = self.bin_to_dec(self.addr)

        control_dec = self.bin_to_dec(self.control)

        protocol_dec = self.bin_to_dec(self.protocol)

        payload_code = self.byte_stuff("00000010")
        self.payload = self.byte_stuff(payload_code + self.payload[8:len(self.payload)])

        lcp_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.mod2div_tx(mensaje=lcp_bin_sin_fcs)
        fcs_dec = self.bin_to_dec(self.byte_stuff(self.FCS))

        lcp_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        lcp_hex_dos = lcp_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

        # print(lcp_hex_dos)
        time.sleep(2)
        self.enviar(lcp_hex_dos)
        
        self.frameCHAP_challenge_tx()

    def frameCHAP_challenge_tx(self):
        flag_dec = self.bin_to_dec(self.flag)

        addr_dec = self.bin_to_dec(self.addr)

        control_dec = self.bin_to_dec(self.control)

        protocol_hex_in = "C223"
        self.protocol = self.hex_to_bin(protocol_hex_in)
        protocol_dec = self.bin_to_dec(self.protocol)

        payload_code_bin = self.byte_stuff("00000001")

        payload_id_dec = random.randint(0, 256)
        payload_id_bin = self.decimalToBinary(payload_id_dec)
        if len(payload_id_bin) < 8:
            payload_id_bin = "0" * (8 - len(payload_id_bin)) + payload_id_bin
        # payload_id_bin = "00000101"
        payload_id_bin = self.byte_stuff(payload_id_bin)

        val_ale_dec = random.randint(0, 64)
        # val_ale_dec = 10
        self.val_ale = self.decimalToBinary(val_ale_dec)
        if len(self.val_ale) < 16:
            self.val_ale = "0" * (16 - len(self.val_ale)) + self.val_ale

        self.password = self.str_bin(self.password)

        mensaje_bin = self.password + self.val_ale

        crc_response_value_bin = self.mod2div_tx(mensaje_bin)
        self.crc_chap = crc_response_value_bin

        challenge_lenght_dec = int(len(self.val_ale) / 8)
        challenge_lenght_bin = self.decimalToBinary(challenge_lenght_dec)
        if len(challenge_lenght_bin) < 8:
            challenge_lenght_bin = "0" * (8 - len(challenge_lenght_bin)) + challenge_lenght_bin
        challenge_lenght_bin = self.byte_stuff(challenge_lenght_bin)

        challenge_name_bin = self.str_bin(self.name)
        lon_name = int(len(self.name) * 8)
        if len(challenge_name_bin) < lon_name:
            challenge_name_bin = "0" * (lon_name - len(challenge_name_bin)) + challenge_name_bin

        payload_info_bin = self.val_ale + challenge_name_bin
        payload_info_bin_stuff = self.byte_stuff(payload_info_bin)

        payload_length = int(len(payload_info_bin) / 8)
        payload_length_bin = self.decimalToBinary(payload_length)
        if len(payload_length_bin) < 16:
            payload_length_bin = "0" * (16 - len(payload_length_bin)) + payload_length_bin
        payload_length_bin = self.byte_stuff(payload_length_bin)

        self.payload = payload_code_bin + payload_id_bin + payload_length_bin + challenge_lenght_bin + payload_info_bin_stuff

        chap_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.mod2div_tx(mensaje=chap_bin_sin_fcs)
        fcs_dec = self.bin_to_dec(self.byte_stuff(self.FCS))

        chap_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        chap_hex_dos = chap_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

        # print(chap_hex_dos)
        time.sleep(2)
        self.enviar(chap_hex_dos)

        self.frameCHAP_response_rx()

    def frameCHAP_response_rx(self):
        # response_rx = b'~\xff\x03\xc2#00000010000001010000000000001000000001001110000100110100010110000001000000001001001111001111000011100011\x00\x00\x00\x00\x1d\\A\xd8~'
        response_rx_tupla = self.recibir()
        response_rx = response_rx_tupla[0]

        response_flag_dec = response_rx[0]
        self.flag = self.decimalToBinary(response_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        response_addr_dec = response_rx[1]
        self.addr = self.decimalToBinary(response_addr_dec)

        response_control_dec = response_rx[2]
        self.control = self.decimalToBinary(response_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        response_protocol = struct.unpack("!H", response_rx[3:5])
        self.protocol = self.decimalToBinary(response_protocol[0])

        conf_req_payload_bin = response_rx[5:len(response_rx) - 9].decode("utf-8")
        self.payload = conf_req_payload_bin

        response_fcs = struct.unpack("!Q", response_rx[len(response_rx) - 9:len(response_rx) - 1])
        response_fcs_dec = response_fcs[0]
        response_fcs_bin = self.decimalToBinary(response_fcs_dec)
        if len(response_fcs_bin) < 32:
            response_fcs_bin = "0" * (32 - len(response_fcs_bin)) + response_fcs_bin
        self.FCS = self.byte_unstuff(response_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            self.frameCHAP_success_failure_tx()
        else:
            print("Datos recibidos con errores")
            self.frameLCP_configure_request_rx()

    def frameCHAP_success_failure_tx(self):
        lon_response = self.bin_to_dec(self.payload[32:40])
        if self.payload[40:40+(lon_response * 8)] == self.crc_chap:
            flag_bin = self.flag
            flag_dec = self.bin_to_dec(flag_bin)

            addr_bin = self.addr
            addr_dec = self.bin_to_dec(addr_bin)

            control_bin = self.control
            control_dec = self.bin_to_dec(control_bin)

            protocol_bin = self.protocol
            protocol_dec = self.bin_to_dec(protocol_bin)

            payload_code_success_bin = "00000011"

            payload_id_success_bin = self.payload[8:16]

            mensaje_str = "Success"
            lon_mensaje = int((len(mensaje_str) * 8))
            mensaje_bin = self.str_bin(mensaje_str)
            if len(mensaje_bin) < lon_mensaje:
                mensaje_bin = "0" * (lon_mensaje - len(mensaje_bin)) + mensaje_bin

            payload_length_success_dec = int(len(mensaje_bin) / 8)
            payload_length_success_bin = self.decimalToBinary(payload_length_success_dec)
            if len(payload_length_success_bin) < 16:
                payload_length_success_bin = "0" * (16 - len(payload_length_success_bin)) + payload_length_success_bin

            self.payload = payload_code_success_bin + payload_id_success_bin + payload_length_success_bin + mensaje_bin
            self.payload = self.byte_stuff(self.payload)

            success_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
            self.FCS = self.mod2div_tx(mensaje=success_bin_sin_fcs)
            fcs_dec = self.bin_to_dec(self.byte_stuff(self.FCS))

            success_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
            success_hex_dos = success_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

            # print(success_hex_dos)
            time.sleep(2)
            self.enviar(success_hex_dos)

            self.frameIPCP_configure_request_rx()
        else:
            flag_bin = self.flag
            flag_dec = self.bin_to_dec(flag_bin)

            addr_bin = self.addr
            addr_dec = self.bin_to_dec(addr_bin)

            control_bin = self.control
            control_dec = self.bin_to_dec(control_bin)

            protocol_bin = self.protocol
            protocol_dec = self.bin_to_dec(protocol_bin)

            payload_code_failure_bin = "00000100"

            payload_id_failure_bin = self.payload[8:16]

            mensaje_str = "Failure"
            lon_mensaje = int((len(mensaje_str) * 8))
            mensaje_bin = self.str_bin(mensaje_str)
            if len(mensaje_bin) < lon_mensaje:
                mensaje_bin = "0" * (lon_mensaje - len(mensaje_bin)) + mensaje_bin

            payload_length_failure_dec = int(len(mensaje_bin) / 8)
            payload_length_failure_bin = self.decimalToBinary(payload_length_failure_dec)
            if len(payload_length_failure_bin) < 16:
                payload_length_failure_bin = "0" * (16 - len(payload_length_failure_bin)) + payload_length_failure_bin

            self.payload = payload_code_failure_bin + payload_id_failure_bin + payload_length_failure_bin + mensaje_bin
            self.payload = self.byte_stuff(self.payload)

            failure_bin_sin_fcs = self.flag + self.addr + self.control + self.protocol + self.payload
            self.FCS = self.mod2div_tx(mensaje=failure_bin_sin_fcs)
            fcs_dec = self.bin_to_dec(self.byte_stuff(self.FCS))

            failure_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
            failure_hex_dos = failure_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

            # print(success_hex_dos)
            time.sleep(2)
            self.enviar(failure_hex_dos)

            print("Error de contraseña")
            self.frameLCP_terminate_request_rx()

    def frameIPCP_configure_request_rx(self):
        # conf_req_rx = b'~\xff\x03\x80!000000010000100000000000000001000111110101111110011111010111111001111101011111100111110101111110\x00\x00\x00\x00\xcb\xd7\x10\xf4~'
        conf_req_rx_tupla = self.recibir()
        conf_req_rx = conf_req_rx_tupla[0]

        conf_req_flag_dec = conf_req_rx[0]
        self.flag = self.decimalToBinary(conf_req_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        conf_req_addr_dec = conf_req_rx[1]
        self.addr = self.decimalToBinary(conf_req_addr_dec)

        conf_req_control_dec = conf_req_rx[2]
        self.control = self.decimalToBinary(conf_req_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        conf_req_protocol = struct.unpack("!H", conf_req_rx[3:5])
        self.protocol = self.decimalToBinary(conf_req_protocol[0])

        conf_req_payload_bin = conf_req_rx[5:len(conf_req_rx) - 9].decode("utf-8")
        self.payload = conf_req_payload_bin

        conf_req_fcs = struct.unpack("!Q", conf_req_rx[len(conf_req_rx) - 9:len(conf_req_rx) - 1])
        conf_req_fcs_dec = conf_req_fcs[0]
        conf_req_fcs_bin = self.decimalToBinary(conf_req_fcs_dec)
        if len(conf_req_fcs_bin) < 32:
            conf_req_fcs_bin = "0" * (32 - len(conf_req_fcs_bin)) + conf_req_fcs_bin
        self.FCS = self.byte_unstuff(conf_req_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            self.frameIPCP_configure_ack_tx()
        else:
            print("Datos recibidos con errores")
            self.frameLCP_configure_request_rx()

    def frameIPCP_configure_ack_tx(self):
        flag_dec = self.bin_to_dec(self.flag)

        addr_dec = self.bin_to_dec(self.addr)

        control_dec = self.bin_to_dec(self.control)

        protocol_dec = self.bin_to_dec(self.protocol)

        payload_code = self.byte_stuff("00000010")
        self.payload = self.byte_stuff(payload_code + self.payload[8:len(self.payload)])

        ipcp_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.mod2div_tx(mensaje=ipcp_bin_sin_fcs)
        fcs_dec = self.bin_to_dec(self.byte_stuff(self.FCS))

        ipcp_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        ipcp_hex_dos = ipcp_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

        # print(ipcp_hex_dos)
        time.sleep(2)
        self.enviar(ipcp_hex_dos)

        self.data_transfer_server()

    def frameIP_rx(self):
        # ip_rx = b'~\xff\x03\x00!Hola\x00\x00\x00\x00/\x84+(~'
        # ip_rx = b'~\xff\x03\x00!adios\x00\x00\x00\x003R\x9b\xcc~'
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
            print("Usuario ", self.name, ": ")
            print(ip_payload)
            if ip_payload == "adios" or ip_payload == "Adios" or ip_payload == "ADIOS":
                self.frameLCP_terminate_request_rx()
            else:
                self.frameIP_tx()
        else:
            print("Datos recibidos con errores")
            self.frameLCP_terminate_request_rx()

    def frameIP_tx(self):
        flag_dec = self.bin_to_dec(self.flag)

        addr_dec = self.bin_to_dec(self.addr)

        control_dec = self.bin_to_dec(self.control)

        protocol_dec = self.bin_to_dec(self.protocol)

        print("Server :")

        payload_user_data_str = input()
        payload_user_data_bin = self.str_bin(payload_user_data_str)
        lon_payload = len(payload_user_data_str) * 8
        if len(payload_user_data_bin) < lon_payload:
            payload_user_data_bin = "0" * (lon_payload - len(payload_user_data_bin)) + payload_user_data_bin

        self.payload = self.byte_stuff(payload_user_data_bin)

        ip_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.byte_stuff(self.mod2div_tx(mensaje=ip_bin_sin_fcs))
        fcs_dec = self.bin_to_dec(self.FCS)

        ip_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        ip_hex_dos = ip_hex_uno + payload_user_data_str.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

        # print(ip_hex_dos)
        time.sleep(2)
        self.enviar(ip_hex_dos)

        self.frameIP_rx()

    def data_transfer_server(self):
        self.frameIP_rx()

    def frameLCP_terminate_request_rx(self):
        # terminate_req_rx = b'~\xff\x03\xc0!000001010000100100000000000001000111110101111110011111010111111001111101011111100111110101111110\x00\x00\x00\x00 \xfeHD~'
        terminate_req_rx_tupla = self.recibir()
        terminate_req_rx = terminate_req_rx_tupla[0]

        term_req_flag_dec = terminate_req_rx[0]
        self.flag = self.decimalToBinary(term_req_flag_dec)
        if len(self.flag) < 8:
            self.flag = "0" * (8 - len(self.flag)) + self.flag

        term_req_addr_dec = terminate_req_rx[1]
        self.addr = self.decimalToBinary(term_req_addr_dec)

        term_req_control_dec = terminate_req_rx[2]
        self.control = self.decimalToBinary(term_req_control_dec)
        if len(self.control) < 8:
            self.control = "0" * (8 - len(self.control)) + self.control

        term_req_protocol = struct.unpack("!H", terminate_req_rx[3:5])
        self.protocol = self.decimalToBinary(term_req_protocol[0])

        term_req_payload_bin = terminate_req_rx[5:len(terminate_req_rx) - 9].decode("utf-8")
        self.payload = term_req_payload_bin

        term_req_fcs = struct.unpack("!Q", terminate_req_rx[len(terminate_req_rx) - 9:len(terminate_req_rx) - 1])
        term_req_fcs_dec = term_req_fcs[0]
        term_req_fcs_bin = self.decimalToBinary(term_req_fcs_dec)
        if len(term_req_fcs_bin) < 32:
            term_req_fcs_bin = "0" * (32 - len(term_req_fcs_bin)) + term_req_fcs_bin
        self.FCS = self.byte_unstuff(term_req_fcs_bin)

        valida = self.mod2div_rx(mensaje=self.addr + self.control + self.protocol + self.payload,
                                 polinomio_crc_tx=self.FCS, polinomio_crc="100000100100000010000110110110101")

        self.payload = self.byte_unstuff(self.payload)

        if valida == "00000000000000000000000000000000":
            self.frameLCP_terminate_ack_tx()
        else:
            print("Datos recibidos con errores")
            self.frameLCP_configure_request_rx()

    def frameLCP_terminate_ack_tx(self):
        flag_dec = self.bin_to_dec(self.flag)

        addr_dec = self.bin_to_dec(self.addr)

        control_dec = self.bin_to_dec(self.control)

        protocol_dec = self.bin_to_dec(self.protocol)

        payload_code = "00000110"

        self.payload = self.byte_stuff(payload_code + self.payload[8:len(self.payload)])

        lcp_bin_sin_fcs = self.addr + self.control + self.protocol + self.payload
        self.FCS = self.mod2div_tx(mensaje=lcp_bin_sin_fcs)
        fcs_dec = self.bin_to_dec(self.byte_stuff(self.FCS))

        lcp_hex_uno = struct.pack("!BBBH", flag_dec, addr_dec, control_dec, protocol_dec)
        lcp_hex_dos = lcp_hex_uno + self.payload.encode("utf-8") + struct.pack("!QB", fcs_dec, flag_dec)

        # print(lcp_hex_dos)
        time.sleep(2)
        self.enviar(lcp_hex_dos)

        self.frameLCP_configure_request_rx()


def main():
    framePPP = socketPPP()
    framePPP.frameLCP_configure_request_rx()


main()
