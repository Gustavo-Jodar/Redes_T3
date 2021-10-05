from grader.iputils import *
import ipaddress

class IP:
    def __init__(self, enlace):
        """
        Inicia a camada de rede. Recebe como argumento uma implementação
        de camada de enlace capaz de localizar os next_hop (por exemplo,
        Ethernet com ARP).
        """
        self.callback = None
        self.enlace = enlace
        self.enlace.registrar_recebedor(self.__raw_recv)
        self.ignore_checksum = self.enlace.ignore_checksum
        self.meu_endereco = None

        self.contador = 0

    def __raw_recv(self, datagrama):
        dscp, ecn, identification, flags, frag_offset, ttl, proto, \
           src_addr, dst_addr, payload = read_ipv4_header(datagrama)
        
        datagrama_recebido = datagrama[:28]

        if dst_addr == self.meu_endereco:
            # atua como host
            if proto == IPPROTO_TCP and self.callback:
                self.callback(src_addr, dst_addr, payload)
        else:
            # atua como roteador
            next_hop = self._next_hop(dst_addr)
            # TODO: Trate corretamente o campo TTL do datagrama
    
            ttl = ttl - 1
            #gera cabeçalho para colocar no cal_checksum
            datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(payload), self.contador, 0, ttl, IPPROTO_TCP, 0) + str2addr(src_addr) + str2addr(dst_addr)
            checksum = calc_checksum(datagrama)
            #monta datagrama com o checksum e payload
            datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(payload), self.contador, 0, ttl, IPPROTO_TCP, checksum) + str2addr(src_addr) + str2addr(dst_addr) + payload
            
            #enviar o datagrama para o remetente com protocólo ICMP
            if(ttl == 0):
                next_hop = self._next_hop(src_addr)

                #monta novo payload com mensagem do ICMP num_max_envios alcançados
                ICMP_message = struct.pack('!BBHI', 11, 0, 0, 0) + datagrama_recebido
                checksum = calc_checksum(ICMP_message)
                ICMP_message = struct.pack('!BBHI', 11, 0, checksum, 0) + datagrama_recebido
 
                datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(ICMP_message), self.contador, 0, 64, IPPROTO_ICMP, 0) + str2addr(self.meu_endereco) + str2addr(src_addr)
                checksum = calc_checksum(datagrama)
                datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(ICMP_message), self.contador, 0, 64, IPPROTO_ICMP, checksum) + str2addr(self.meu_endereco) + str2addr(src_addr) + ICMP_message
            
            self.enlace.enviar(datagrama, next_hop)
                

    def _next_hop(self, dest_addr):
        # TODO: Use a tabela de encaminhamento para determinar o próximo salto
        # (next_hop) a partir do endereço de destino do datagrama (dest_addr).
        # Retorne o next_hop para o dest_addr fornecido.
        dest_addr = dest_addr
        n = 0
        to = None
        for hop in self.tabela:
            if(ipaddress.ip_address(dest_addr) in ipaddress.ip_network(hop[0]) and int(hop[0].split("/")[1]) >= n):
                n = int(hop[0].split("/")[1])
                to = hop[1]
        
        return to
            
        

    def definir_endereco_host(self, meu_endereco):
        """
        Define qual o endereço IPv4 (string no formato x.y.z.w) deste host.
        Se recebermos datagramas destinados a outros endereços em vez desse,
        atuaremos como roteador em vez de atuar como host.
        """
        self.meu_endereco = meu_endereco

    def definir_tabela_encaminhamento(self, tabela):
        """
        Define a tabela de encaminhamento no formato
        [(cidr0, next_hop0), (cidr1, next_hop1), ...]

        Onde os CIDR são fornecidos no formato 'x.y.z.w/n', e os
        next_hop são fornecidos no formato 'x.y.z.w'.
        """
        # TODO: Guarde a tabela de encaminhamento. Se julgar conveniente,
        # converta-a em uma estrutura de dados mais eficiente.
        self.tabela = tabela

    def registrar_recebedor(self, callback):
        """
        Registra uma função para ser chamada quando dados vierem da camada de rede
        """
        self.callback = callback

    def enviar(self, segmento, dest_addr):
        """
        Envia segmento para dest_addr, onde dest_addr é um endereço IPv4
        (string no formato x.y.z.w).
        """
        
        #criando primeira vez antes de passar no checksum
        datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(segmento), self.contador, 0, 64, 6, 0) + str2addr(self.meu_endereco) + str2addr(dest_addr)
        #calcula checksum
        checksum = calc_checksum(datagrama)
        #monta o datagrama já com o checksum e com o segmento no final
        datagrama = struct.pack('!BBHHHBBH', 69, 0, 20+len(segmento), self.contador, 0, 64, 6, checksum) + str2addr(self.meu_endereco) + str2addr(dest_addr) + segmento
        
        next_hop = self._next_hop(dest_addr)
        # TODO: Assumindo que a camada superior é o protocolo TCP, monte o
        # datagrama com o cabeçalho IP, contendo como payload o segmento.

        self.contador = self.contador + 1

        self.enlace.enviar(datagrama, next_hop)
