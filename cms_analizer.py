#!/usr/bin/python
# -*- coding: utf-8 -*-
#UNAM-CERT

#-------------Integrantes---------------------
#   Manzano Cruz Isaias Abraham
#   Espinosa Curiel Oscar
#---------------------------------------------
#--------------IMPORTANTE---------------------
#       Instalar BeautifulSoup
#	    pip install BeautifulSoup
#---------------------------------------------

import sys
import optparse
import ConfigParser
import httplib
import ssl
import OpenSSL
import json
from BeautifulSoup import BeautifulSoup
from time import sleep
from requests import get, put, options, post, delete, head, patch, session
from requests.exceptions import ConnectionError
from re import search
from datetime import datetime
from random import choice

def addOptions():
    '''
    Funcion que parsea los datos que se tomen de linea de comandos como opciones para ejecutar el programa
    Devuelve un objeto cuyos atributos son las opciones de ejecucion
    '''
    parser = optparse.OptionParser()
    parser.add_option('-u','--url', dest='url', default=None, help='Indica la URL para realizar el ataque, formato: {http|https}://{ip|domainname}[/directorio]:puerto')
    parser.add_option('-v', '--verbose', action='store_true',dest='verbose', default=False, help='Si es activado el script mostrara informacion de las peticiones que se realizan')
    parser.add_option('-r', '--report', dest='report', default='reporte.txt', help='Indica el nombre del archivo de reporte')
    parser.add_option('-U', '--useragent', dest='useragent', default=None, help='Indica el User-Agent a usar, o un archivo con User-Agents')
    parser.add_option('-c', '--config', dest='config', default=None, help='Indica el archivo JSON de configuracion para ejecutar la herramienta')
    opts,args = parser.parse_args()
    return opts


def print_verbose(message,verbose):
    '''
    Funcion que recibe un mensaje como parametro, el cual dira que es lo que esta haciendo.
    '''
    if verbose and len(message)>1:
        print message

    
def checkOptions(options):
    '''
    Funcion que verifica las opciones minimas para que el programa pueda correr correctamente, en caso de no cumplir con los requerimientos minimos
    el programa termina su ejecucion
    Recibe un objeto con las opciones de ejecucion del programa
    '''
    if options.url is None:
        printError('Desbes especificar un server para atacar.', True)
    if options.config is None:
        printError('Desbes especificar un archivo de configuracion',True)

 
def verify_url(url):
    '''
    Funcion que verifica los argumentos minimos para poder ejecutar el programa
    '''
    http_re=r"(http://.*:[0-9]{2}(/.*)?/$)"
    https_re=r"(https://.*:[0-9]{3}(/.*)?/$)"
    if search(http_re,url):
        return 'http'
    elif search(https_re,url):
        return 'https'
    else:
        printError('URL no valida:%s'%url,True)
      

def printError(msg, exit = False):

    '''
    Esta funcion imprime en la salida de error estandar un mensaje
    Recibe:	
	msg:	mensaje a imprimir y exit:  exit el cual indica si el el programa termina su ejecucion o no
	exit:	Si es True termina la ejecucion del programa
    '''
    sys.stderr.write('Error:\t%s\n' % msg)
    if exit:
        sys.exit(1)


def create_report(webpage, options, report_file):
    '''
    Esta funcion crea el archivo de reporte
    '''
    with open(report_file, 'w') as f_report:
        print 'El archivo: "' + report_file + '", sera creado con la informacion del reporte'
        f_report.write(' Archivo reporte '.center(70,'=')+'\n\n')
        f_report.write('Hora de ejecucion: ' + str(datetime.now()) + '\n' + 'Server analizado: ' + webpage + '\n' + 'Opciones de ejecucion: ' + str(options)[1:-1].replace("'",'') + '\n')
   
def print_report(message, report_file):
    '''
    Esta funcion escribe un mensaje en el archivo de reporte"
    Recibe:	
    	message: el mensaje a imprimir en el archivo de resultados
    '''
    with open(report_file,'a') as f_report:
        f_report.write(message+'\n')
        f_report.close()


def metodos_http(url):
    '''
    Esta funcion se encarga de revisar los metodos http habilitados en un servidor
    Recibe:
    	url:	servidor a analizar
    Regresa:
    	salida:	cadena con informacion de los metodos habilitados
    '''

    salida="Metodos http que contiene la direccion:\n"
    if put(url).status_code == 200:
        salida+= "Tiene metodo put\n"
    if get(url).status_code == 200:
        salida+= "Tiene metodo get\n"
    if options(url).status_code == 200:
        salida+= "Tiene metodo options\n"
    if post(url).status_code == 200:
        salida+= "Tiene metodo post\n"
    if delete(url).status_code == 200:
        salida+= "Tiene metodo delete\n"
    if head(url).status_code == 200:
        salida+= "Tiene metodo head\n"
    if patch(url).status_code == 200:
        salida+= "Tiene metodo patch\n"
    return salida


def informacion(url):
    '''
    Funcion que recibe como parametro la url y obtiene a traves de los encabezados HTTP informacion del servidor, que tipo de servidor es 'Server' y el 'X-Powered-By' y en caso de utilizar csm muestra cual utiliza, devolviendo el servidor el x-powered-by y el csm, los cuales se escribiran en el reporte.
    '''
    #Corregir, no muestra el CMS
    server = ''
    powered = ''
    cms = ''
    texto1 = "Version del servidor: "
    texto2 = "X-Powered-By: "
    texto3 = "CSM: "
    r = get(url)
    cabeceras = r.headers
    html = r.content
    parsed_html = BeautifulSoup(html)
    if 'Server' in cabeceras:
        server = cabeceras['Server']
        server = texto1 + server
    if 'X-Powered-By' in cabeceras:
        powered = cabeceras['X-Powered-By']
        powered = texto2 + powered
    for var in parsed_html.findAll('meta'):
        var2 = var.get('name')
        if var2 == 'generator':
            cms = var.get('content')
            cms = texto3 + csm
    return server, powered, cms


def certificados(url):
    '''
    Funcion que recibe como parametro la url y obtiene informacion del certificado, si es que utiliza https, regresando la informacion del certificado la cual se escribira en el archivo.
    '''
    texto = "Informacion del certificado: "
    url2=url.split(':')[1][2:]
    cert = ssl.get_server_certificate((url2, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    informacion = str(x509.get_subject().get_components())
    informacion = texto + informacion
    try:
        req=get(url,verify=True)
        message = 'El servidor tiene un certificado valido'
    except:
        message = 'El servdor tiene un certificado no valido'
    return informacion,message


def make_agent(agent):
    '''
    Funcion que devuelve una lista, con los agentes a utiliar en cada peticion
    Recibe un archivo o una opcion dada por la linea de comandos
    Devuelve una lista con el/los agente(s)
    '''
    try:
        return open(agent).read().splitlines()
    except:
        return [agent]

def make_requests(url, verbose, user_agent, protocol, report, files='common.txt', extractv=True, methods=True, ssl_tls=True, time=0.05):
    '''
	Funcion que hace las peticiones al sitio web que se quiere atacar
	Recibe la url, si se desea imprimir mensajes con verbose, el archivo de de donde va a sacar los archivos a buscar
	el user-agent que el programa utilizara, extractv que indica si se va a obtener informacion del html, methods para 
	indicar si se va a obtener los metdos que tiene habilitado el sitio, ssl_tls para obtener informacion de los certificados
	protocol para validar que si se va a obtener informacion de los certificados sea una pagina por https, results que indica
	el archivo donde se escribiran los resultados, report que es el archivo de reporte y el tiempo de espera entre cada peticion
    '''
    cont=0
    try:
        if methods:
            message1 = metodos_http(url)
            print_verbose(message1,verbose)
            print_report(message1,report)
        if ssl_tls and protocol == 'https':
            info,certs = certificados(url)
            print_verbose(info,verbose)
            print_verbose(certs,verbose)
            print_report(info,report)
            print_report(certs,report)
        if extractv:
            server,powered,cms=informacion(url)
            print_verbose(server,verbose)
            print_verbose(powered,verbose)
            print_verbose(cms,verbose)
            print_report(server,report)
            print_report(powered,report)
            print_report(cms,report)
    	with open(files, 'r') as f_files:
            for fl in f_files:
                fl = fl.strip('\n')
                url_file=url+fl
                s=session()
                headers={}
                headers['User-agent']=choice(user_agent)
                response=s.get(url_file,headers=headers)
                if (response.status_code == 200 or response.status_code > 300) and (response.status_code < 400):
                    leng = len(response.content)
                    message='\t%s : File found    |    lenght:%d    |    (CODE:%d)' %(fl,leng,response.status_code)
                    print_verbose(message, verbose)
                    print_report(message, report)
                    cont+=1
        	else:
                    message='\t%s : File not found    |    (CODE:%s)' %(fl,str(response.status_code))
                    print_verbose(message, verbose)
                    print_report(message, 'Errores_4XX.txt')
            	sleep(time)
    except ConnectionError:
        printError('Error en la conexion, tal vez el servidor no esta arriba.',True)
    finally:
        print_report('\nSe encontraron: %d archivos en el servidor'%cont,report)

def read_cmsJSON(opts):
    """
        Funcion que lee y parsea el archivo json con la configuracion del script
        para la busqueda del CMS

        devuelve una instancia json
    """
    try:
        print_verbose('Leyendo archivo ' + opts.config, opts.verbose)
        return json.loads(open(opts.config).read())
    
    except IOError:
        printError('El archivo ' + opts.config + ' no existe o no se tiene permisos de lectura',True)    
    
    except ValueError:
        printError('El archivo ' + opts.config + ' no es formato JSON', True)

def concat(cms_url, resource, is_subdir = False):
    """
        Funcion que concatena la URL del sitio con un recurso leido del json
        retorna la url completa
        Si se desea concatenar un subdirectorio se debe hacer True el parametro is_subdir
    """
    if is_subdir:
        #si es subdirectorio, agregamos un / al final de la url
        return cms_url + resource + '/' if cms_url[len(cms_url) - 1] == '/' else cms_url + '/' + resource + '/'
    else:
        return cms_url + resource if cms_url[len(cms_url) - 1] == '/' else cms_url + '/' + resource
    

def check_subdirs(opts, cms_json):
    """
        Funcion que hace una peticion HEAD al recurso dado para verificar que
        existe, en orden de conocer el CMS objetivo
    """
    if 'check_subdirs' in cms_json.keys():
        print_verbose('Buscando subdirectorios', opts.verbose)
        
        #iteramos sobre todos los subdirs dados
        for s in cms_json['check_subdirs'].keys():
            if head(concat(opts.url, cms_json['check_subdirs'][s], True)).status_code == 200:
                #Existe al menos un subdirectorio dado, lo que nos dice que si es el
                #CMS esperado
                print_verbose('CMS ENCONTRADO!!!!', opts.verbose)
                print_verbose('------> CMS: ' + cms_json['cms'] + '<--------', True)
                
                return True
        
        #Llegado a este punto, no hubo ninguna respuesta 200 a los recursos
        print_verbose('No se encontro coincidencia con subdirectorios dados', opts.verbose)
        return False
    else:
        print_verbose('No se dieron subdirectorios a buscar', opts.verbose)
        return False
        

def main_cms_analizer():
    """
        Funcion principal del script
    """
    #try:
    opts = addOptions()
    checkOptions(opts)
    #En este punto ya se reviso existencia de -u y -c
    cms_json = read_cmsJSON(opts)
    check_subdirs(opts, cms_json)
    """
    protocol = verify_url(opts.url)
    create_report(opts.url, opts, opts.report)
    if opts.useragent == None or opts.useragent=='':
        user_agent=make_agent('user_agents.txt')
    else:
        user_agent=make_agent(opts.useragent)        
    make_requests(opts.url, opts.verbose, user_agent, protocol, opts.report)

    #except Exception as e:
    printError('An unexpected error happend :(')
    printError(e, True)
    """



if __name__ == '__main__':
    main_cms_analizer()