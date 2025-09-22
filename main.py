class MFRC522:

	OK = 0
	NOTAGERR = 1
	ERR = 2

	REQIDL = 0x26
	REQALL = 0x52
	AUTHENT1A = 0x60
	AUTHENT1B = 0x61

	def __init__(self, spi, cs):

		self.spi = spi
		self.cs = cs
		self.cs.value(1)
		#self.spi.init()
		self.init()

	def _wreg(self, reg, val):

		self.cs.value(0)
		self.spi.write(b'%c' % int(0xff & ((reg << 1) & 0x7e)))
		self.spi.write(b'%c' % int(0xff & val))
		self.cs.value(1)

	def _rreg(self, reg):

		self.cs.value(0)
		self.spi.write(b'%c' % int(0xff & (((reg << 1) & 0x7e) | 0x80)))
		val = self.spi.read(1)
		self.cs.value(1)

		return val[0]

	def _sflags(self, reg, mask):
		self._wreg(reg, self._rreg(reg) | mask)

	def _cflags(self, reg, mask):
		self._wreg(reg, self._rreg(reg) & (~mask))

	def _tocard(self, cmd, send):

		recv = []
		bits = irq_en = wait_irq = n = 0
		stat = self.ERR

		if cmd == 0x0E:
			irq_en = 0x12
			wait_irq = 0x10
		elif cmd == 0x0C:
			irq_en = 0x77
			wait_irq = 0x30

		self._wreg(0x02, irq_en | 0x80)
		self._cflags(0x04, 0x80)
		self._sflags(0x0A, 0x80)
		self._wreg(0x01, 0x00)

		for c in send:
			self._wreg(0x09, c)
		self._wreg(0x01, cmd)

		if cmd == 0x0C:
			self._sflags(0x0D, 0x80)

		i = 2000
		while True:
			n = self._rreg(0x04)
			i -= 1
			if ~((i != 0) and ~(n & 0x01) and ~(n & wait_irq)):
				break

		self._cflags(0x0D, 0x80)

		if i:
			if (self._rreg(0x06) & 0x1B) == 0x00:
				stat = self.OK

				if n & irq_en & 0x01:
					stat = self.NOTAGERR
				elif cmd == 0x0C:
					n = self._rreg(0x0A)
					lbits = self._rreg(0x0C) & 0x07
					if lbits != 0:
						bits = (n - 1) * 8 + lbits
					else:
						bits = n * 8

					if n == 0:
						n = 1
					elif n > 16:
						n = 16

					for _ in range(n):
						recv.append(self._rreg(0x09))
			else:
				stat = self.ERR

		return stat, recv, bits

	def _crc(self, data):

		self._cflags(0x05, 0x04)
		self._sflags(0x0A, 0x80)

		for c in data:
			self._wreg(0x09, c)

		self._wreg(0x01, 0x03)

		i = 0xFF
		while True:
			n = self._rreg(0x05)
			i -= 1
			if not ((i != 0) and not (n & 0x04)):
				break

		return [self._rreg(0x22), self._rreg(0x21)]

	def init(self):

		self.reset()
		self._wreg(0x2A, 0x8D)
		self._wreg(0x2B, 0x3E)
		self._wreg(0x2D, 30)
		self._wreg(0x2C, 0)
		self._wreg(0x15, 0x40)
		self._wreg(0x11, 0x3D)
		self.antenna_on()

	def reset(self):
		self._wreg(0x01, 0x0F)

	def antenna_on(self, on=True):

		if on and ~(self._rreg(0x14) & 0x03):
			self._sflags(0x14, 0x03)
		else:
			self._cflags(0x14, 0x03)

	def request(self, mode):

		self._wreg(0x0D, 0x07)
		(stat, recv, bits) = self._tocard(0x0C, [mode])

		if (stat != self.OK) | (bits != 0x10):
			stat = self.ERR

		return stat, bits

	def anticoll(self):

		ser_chk = 0
		ser = [0x93, 0x20]

		self._wreg(0x0D, 0x00)
		(stat, recv, bits) = self._tocard(0x0C, ser)

		if stat == self.OK:
			if len(recv) == 5:
				for i in range(4):
					ser_chk = ser_chk ^ recv[i]
				if ser_chk != recv[4]:
					stat = self.ERR
			else:
				stat = self.ERR

		return stat, recv

	def select_tag(self, ser):

		buf = [0x93, 0x70] + ser[:5]
		buf += self._crc(buf)
		(stat, recv, bits) = self._tocard(0x0C, buf)
		return self.OK if (stat == self.OK) and (bits == 0x18) else self.ERR

	def auth(self, mode, addr, sect, ser):
		return self._tocard(0x0E, [mode, addr] + sect + ser[:4])[0]

	def stop_crypto1(self):
		self._cflags(0x08, 0x08)

	def read(self, addr):

		data = [0x30, addr]
		data += self._crc(data)
		(stat, recv, _) = self._tocard(0x0C, data)
		return recv if stat == self.OK else None

	def write(self, addr, data):

		buf = [0xA0, addr]
		buf += self._crc(buf)
		(stat, recv, bits) = self._tocard(0x0C, buf)

		if not (stat == self.OK) or not (bits == 4) or not ((recv[0] & 0x0F) == 0x0A):
			stat = self.ERR
		else:
			buf = []
			for i in range(16):
				buf.append(data[i])
			buf += self._crc(buf)
			(stat, recv, bits) = self._tocard(0x0C, buf)
			if not (stat == self.OK) or not (bits == 4) or not ((recv[0] & 0x0F) == 0x0A):
				stat = self.ERR

		return stat

# Importações necessárias
from machine import Pin, SoftSPI
import time
import json

# Configuração dos pinos para ESP32 (mesma do código de leitura)
sck = Pin(26, Pin.OUT)
mosi = Pin(25, Pin.OUT)
miso = Pin(12, Pin.OUT)
spi = SoftSPI(baudrate=100000, polarity=0, phase=0, sck=sck, mosi=mosi, miso=miso)

sda = Pin(27, Pin.OUT)

# Inicializa o MFRC522
rdr = MFRC522(spi, sda)

print("Escritor de Tag RFID/NFC")
print("Aproxime uma tag para escrever...")

def reset_reader():
    """
    Reseta completamente o leitor RFID
    """
    try:
        rdr.stop_crypto1()
        rdr.antenna_on(False)
        time.sleep(0.1)
        rdr.antenna_on(True)
        time.sleep(0.1)
    except:
        pass

def write_json_to_tag():
    # Dados a serem escritos na tag
    data_to_write = {"name": "Garrafa"}
    json_string = json.dumps(data_to_write)
    
    print(f"=== ESCRITOR RFID INICIANDO ===")
    print(f"Dados a escrever: {json_string}")
    print("Aproxime o cartão para escrever...")
    print("Pressione Ctrl+C para parar\n")
    
    # Chave padrão para autenticação
    auth_key = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    last_uid = ""
    
    # Reset inicial
    reset_reader()
    
    while True:
        try:
            # Detecta cartão
            (stat, tag_type) = rdr.request(rdr.REQIDL)
            if stat == rdr.OK:
                try:
                    (stat, raw_uid) = rdr.anticoll()
                    if stat == rdr.OK and len(raw_uid) >= 4:
                        uid = ("0x%02x%02x%02x%02x" % (raw_uid[0], raw_uid[1], raw_uid[2], raw_uid[3]))
                        
                        # Só processa se for um cartão diferente
                        if uid != last_uid:
                            last_uid = uid
                            print(f"Cartão detectado: {uid}")
                            
                            try:
                                if rdr.select_tag(raw_uid) == rdr.OK:
                                    print("Cartão selecionado! Escrevendo dados...")
                                    
                                    # Prepara dados para escrita
                                    data_bytes = json_string.encode('utf-8')
                                    
                                    # Bloco 1 - primeiro bloco de dados
                                    block1_data = [0] * 16
                                    for i in range(min(16, len(data_bytes))):
                                        block1_data[i] = data_bytes[i]
                                    
                                    # Bloco 2 - segundo bloco se necessário
                                    block2_data = [0] * 16
                                    if len(data_bytes) > 16:
                                        for i in range(min(16, len(data_bytes) - 16)):
                                            block2_data[i] = data_bytes[16 + i]
                                    
                                    success = True
                                    
                                    # Autentica e escreve no bloco 1
                                    if rdr.auth(rdr.AUTHENT1A, 3, auth_key, raw_uid) == rdr.OK:
                                        if rdr.write(1, block1_data) == rdr.OK:
                                            print("Bloco 1 escrito com sucesso!")
                                        else:
                                            print("Erro ao escrever bloco 1")
                                            success = False
                                    else:
                                        print("Erro de autenticação para bloco 1")
                                        success = False
                                    
                                    # Se há mais dados, escreve no bloco 2
                                    if success and len(data_bytes) > 16:
                                        if rdr.auth(rdr.AUTHENT1A, 3, auth_key, raw_uid) == rdr.OK:
                                            if rdr.write(2, block2_data) == rdr.OK:
                                                print("Bloco 2 escrito com sucesso!")
                                            else:
                                                print("Erro ao escrever bloco 2")
                                                success = False
                                        else:
                                            print("Erro de autenticação para bloco 2")
                                            success = False
                                    
                                    if success:
                                        print(f"*** DADOS ESCRITOS COM SUCESSO ***")
                                        print(f"JSON gravado: {json_string}")
                                        
                                        # Verifica a escrita lendo de volta
                                        print("Verificando escrita...")
                                        if rdr.auth(rdr.AUTHENT1A, 3, auth_key, raw_uid) == rdr.OK:
                                            # Lê blocos 1 e 2
                                            all_data = []
                                            for block in [1, 2]:
                                                try:
                                                    data = rdr.read(block)
                                                    if data:
                                                        all_data.extend(data)
                                                except:
                                                    pass
                                            
                                            if all_data:
                                                # Remove bytes nulos e converte para string
                                                clean_bytes = []
                                                for byte in all_data:
                                                    if byte == 0:
                                                        break
                                                    clean_bytes.append(byte)
                                                
                                                if clean_bytes:
                                                    read_string = bytes(clean_bytes).decode('utf-8')
                                                    print(f"Dados lidos da tag: {read_string}")
                                                    
                                                    try:
                                                        read_json = json.loads(read_string)
                                                        print(f"JSON verificado: {read_json}")
                                                        print("*** ESCRITA VERIFICADA COM SUCESSO ***")
                                                    except:
                                                        print("Erro ao parsear JSON lido")
                                                else:
                                                    print("Nenhum dado lido")
                                            else:
                                                print("Erro ao ler dados para verificação")
                                        else:
                                            print("Erro de autenticação na verificação")
                                    
                                else:
                                    print("Falha ao selecionar cartão")
                            except Exception as e:
                                print(f"Erro ao processar cartão: {e}")
                            finally:
                                # SEMPRE limpa o estado
                                reset_reader()
                            
                            print("Remova o cartão e aproxime outro para escrever novamente...\n")
                            print("-" * 50)
                            
                            # Pausa para evitar reescritas
                            time.sleep(2)
                        else:
                            # Mesmo cartão ainda presente
                            time.sleep(0.3)
                    else:
                        time.sleep(0.1)
                except Exception as e:
                    print(f"Erro na detecção: {e}")
                    reset_reader()
                    time.sleep(0.5)
            else:
                # Sem cartão detectado
                if last_uid != "":
                    last_uid = ""
                    print("Cartão removido. Aguardando próximo...")
                time.sleep(0.2)
                
        except KeyboardInterrupt:
            print("\n*** ESCRITOR FINALIZADO PELO USUÁRIO ***")
            reset_reader()
            break
        except Exception as e:
            print(f"Erro geral: {e}")
            print("Resetando leitor...")
            reset_reader()
            time.sleep(1)

# Executa o escritor
if __name__ == "__main__":
    # Aguarda um pouco antes de iniciar
    print("Iniciando sistema em 2 segundos...")
    time.sleep(2)
    
    # Reset inicial completo
    reset_reader()
    
    try:
        write_json_to_tag()
    except KeyboardInterrupt:
        print("\nPrograma interrompido pelo usuário")
        reset_reader()