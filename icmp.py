'''
    icmp.py
    
    Funciones necesarias para implementar el nivel ICMP
    Autor: Javier Ramos <javier.ramos@uam.es>
    2022 EPS-UAM
'''
from ip import *
from threading import Lock
import struct

ICMP_PROTO = 1
ICMP_HLEN=8

ICMP_ECHO_REQUEST_TYPE = 8
ICMP_ECHO_REPLY_TYPE = 0
ICMP_ECHO_CODE = 0

timeLock = Lock()
icmp_send_times = {}

def process_ICMP_message(us,header,data,srcIp):
    '''
        Nombre: process_ICMP_message
        Descripción: Esta función procesa un mensaje ICMP. Esta función se ejecutará por cada datagrama IP que contenga
        un 1 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Calcular el checksum de ICMP y comprobar si es correcto:
            -Extraer campos tipo y código de la cabecera ICMP
            -Loggear (con logging.debug) el valor de tipo y código
            -Si el tipo es ICMP_ECHO_REQUEST_TYPE:
                -Generar un mensaje de tipo ICMP_ECHO_REPLY como respuesta. Este mensaje debe contener
                los datos recibidos en el ECHO_REQUEST. Es decir, "rebotamos" los datos que nos llegan.
                -Enviar el mensaje usando la función sendICMPMessage
            -Si el tipo es ICMP_ECHO_REPLY_TYPE:
                -Extraer del diccionario icmp_send_times el valor de tiempo de envío usando como clave los campos srcIP e icmp_id e icmp_seqnum
                contenidos en el mensaje ICMP. Restar el tiempo de envio extraído con el tiempo de recepción (contenido en la estructura pcap_pkthdr)
                -Se debe proteger el acceso al diccionario de tiempos usando la variable timeLock
                -Mostrar por pantalla la resta. Este valor será una estimación del RTT
            -Si es otro tipo:
                -No hacer nada

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del mensaje ICMP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno
          
    '''
    if len(data) < ICMP_HLEN:
        logging.error('Mensaje ICMP demasiado corto')
        return

    #Comprobar checksum
    if chksum(bytes(data)) != 0:
        logging.error('Checksum ICMP incorrecto')
        return

    #Extraer campos
    icmp_type, icmp_code, checksum, icmp_id, icmp_seqnum = struct.unpack('!BBHHH', data[:ICMP_HLEN])
    payload = data[ICMP_HLEN:]

    #Loggear tipo y código
    logging.debug('Tipo ICMP: ' + str(icmp_type))
    logging.debug('Código ICMP: ' + str(icmp_code) + '\n')

    if icmp_type == ICMP_ECHO_REQUEST_TYPE:
        #Responder si es echo_request
        sendICMPMessage(payload, ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_CODE, icmp_id, icmp_seqnum, srcIp)
    elif icmp_type == ICMP_ECHO_REPLY_TYPE:
        #Calcular el RTT si es echo_reply
        with timeLock:
            sendTime = icmp_send_times[srcIp + icmp_id + icmp_seqnum]
        if sendTime is None:
            return
        recTime = header.ts.tv_sec + header.ts.tv_usec / 1e6
        print('\nRTT: ' + str(recTime - sendTime) + ' segundos\n')

def sendICMPMessage(data,type,code,icmp_id,icmp_seqnum,dstIP):
    '''
        Nombre: sendICMPMessage
        Descripción: Esta función construye un mensaje ICMP y lo envía.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Si el campo type es ICMP_ECHO_REQUEST_TYPE o ICMP_ECHO_REPLY_TYPE:
                -Construir la cabecera ICMP
                -Añadir los datos al mensaje ICMP
                -Calcular el checksum y añadirlo al mensaje donde corresponda
                -Si type es ICMP_ECHO_REQUEST_TYPE
                    -Guardar el tiempo de envío (llamando a time.time()) en el diccionario icmp_send_times
                    usando como clave el valor de dstIp+icmp_id+icmp_seqnum
                    -Se debe proteger al acceso al diccionario usando la variable timeLock

                -Llamar a sendIPDatagram para enviar el mensaje ICMP
                
            -Si no:
                -Tipo no soportado. Se devuelve False

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el mensaje ICMP
            -type: valor del campo tipo de ICMP
            -code: valor del campo code de ICMP 
            -icmp_id: entero que contiene el valor del campo ID de ICMP a enviar
            -icmp_seqnum: entero que contiene el valor del campo Seqnum de ICMP a enviar
            -dstIP: entero de 32 bits con la IP destino del mensaje ICMP
        Retorno: True o False en función de si se ha enviado el mensaje correctamente o no
          
    '''
    if type != ICMP_ECHO_REQUEST_TYPE and type != ICMP_ECHO_REPLY_TYPE:
        logging.error('Tipo ICMP no soportado')
        return False

    #Construir cabecera ICMP (el checksum se pone a 0 y se calcula después)
    icmp_message = bytes()
    icmp_message += struct.pack('!BBHHH', type, code, 0, icmp_id, icmp_seqnum)
    
    #Añadir datos
    icmp_message += data

    #Calcular y añadir checksum
    if len(icmp_message)%2==1:
        checksum = chksum(icmp_message + bytes([0]))
    else:
        checksum = chksum(icmp_message)

    icmp_message = icmp_message[:2] + struct.pack('<H', checksum) + icmp_message[4:]

    #Guardar tiempo de envío si type es ICMP_ECHO_REQUEST_TYPE
    if type == ICMP_ECHO_REQUEST_TYPE:
        with timeLock:
            icmp_send_times[dstIP + icmp_id + icmp_seqnum] = time.time()

    print('Tamaño icmp_message: ' + str(len(icmp_message)))
    #Enviar el mensaje ICMP
    return sendIPDatagram(dstIP, icmp_message, ICMP_PROTO)
   
def initICMP():
    '''
        Nombre: initICMP
        Descripción: Esta función inicializa el nivel ICMP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_ICMP_message con el valor de protocolo 1

        Argumentos:
            -Ninguno
        Retorno: Ninguno
          
    '''
    registerIPProtocol(process_ICMP_message, ICMP_PROTO)