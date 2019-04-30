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
from urlparse import urlparse
from BeautifulSoup import BeautifulSoup
from time import sleep
from requests import get, put, options, post, delete, head, patch, session
from requests.exceptions import ConnectionError
from re import search
from datetime import datetime
from random import choice

#Usada para almacenar el cms detectado en la ejecucion
#la usamos para definir el post en check_login
cms_detected = None

#Usada para almacenar la raiz del sitio dado como argumento al script
cms_root = None

#Diccionario usado para almacenar nombre de input de formulario para POST de login
#y el error que se debe buscar
commons_cms = {
    'Wordpress': ['log', 'pwd', '<div id="login_error">.*The password you entered for the username <strong>.*</strong> is incorrect.']
}

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
    parser.add_option('-w', '--userlist', dest='userlist', default='http_default_users.txt', help='Lista de usuarios existentes a probar en el CMS')
    parser.add_option('-C', '--Common', dest='common', default='common.txt', help='Lista de archivos existentes a probar en el CMS')
    parser.add_option('-n', '--num_plugins', type=int, dest='num_plugins', default=15, help='Numero de plugins instalados a buscar dentro del CMS')
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
    http_re=r"(http://.*[:][0-9]{2}(/.*)?/$)"
    https_re=r"(https://.*[:][0-9]{3}(/.*)?/$)"
    if not search(http_re,url):
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
    return salida[:-1]


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


def make_requests(url, verbose, user_agent, report, files, extractv=True, methods=True, ssl_tls=True, time=0):
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
        print_verbose("\nURL para probar: %s"%url,verbose)
        print_report("URL para probar: %s"%url,report)
        if methods:
            message1 = metodos_http(url)
            print_verbose(message1,verbose)
            print_report(message1,report)
        if extractv:
            server,powered,cms=informacion(url)
            print_verbose(server,verbose)
            print_verbose(powered,verbose)
            print_verbose(cms,verbose)
            print_report(server,report)
            print_report(powered,report)
            print_report(cms,report)
        for fl in files:
            fl = fl.strip('\n')
            url_file=url+fl
            s=session()
            headers={}
            headers['User-agent']=choice(user_agent)
            response=s.get(url_file,headers=headers)
            if (response.status_code == 200 or response.status_code == 403):
                leng = len(response.content)
                message='\t%s : File found    (CODE:%d   |   lenght:%d)' %(fl,response.status_code,leng)
                #print_verbose(message, verbose)
                print(message)
                print_report(message, report)
                cont+=1
            else:
                message='\t%s : File not found    (CODE:%s)' %(fl,str(response.status_code))
                print_verbose(message, verbose)
                #print_report(message, 'Errores_4XX.txt')
                sleep(time)
    except ConnectionError:
        printError('Error en la conexion, tal vez el servidor no esta arriba.',True)
    finally:
        print_report('Se encontraron: %d archivos en el servidor'%cont,report)
        print_verbose('Se encontraron: %d archivos en el servidor'%cont,verbose)
        return cont


def read_cmsJSON(opts):
    """
        Funcion que lee y parsea el archivo json con la configuracion del script
        para la busqueda del CMS

        devuelve una instancia json
    """
    try:
        print_verbose('Leyendo archivo ' + opts.config, opts.verbose)
        print_report('Se intenta leer el archivo ' + opts.config, opts.report)
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


def get_root(opts,files):
    """
        Funcion que nos devuelve la raiz del sitio dado
        a partir de aqui se buscan todos los recursos
    """
    pos=[]
    found = []
    user_agent=make_agent('user_agents.txt')
    recursos=urlparse(opts.url).path.split("/")[1:]
    urls = ['/'+'/'.join(recursos[:x+1]) for x in range(len(recursos))]
    urls.insert(0,'/')
    url= urlparse(opts.url).scheme+'://'+urlparse(opts.url).netloc
    print "######################"
    print urls
    print url
    print "######################"
    for u in urls:
        full_url = url+u
        print "$$$"
        print full_url
        print "$$$"
        n = make_requests(full_url, opts.verbose, user_agent, opts.report,files.values())
        pos.append(full_url)
        found.append(n)
    root = pos[found.index(max(found))][:-1]
    msg = 'Raiz del CMS: '+root+'\n'
    print_verbose(msg,opts.verbose)
    print_report(msg,opts.report)
    return root

def check_subdirs(opts, cms_json, cms_root):
    """
        Funcion que hace una peticion HEAD al recurso dado para verificar que
        existe, en orden de conocer el CMS objetivo.
        Retorna True si hay coincidencia, False en caso contrario
    """

    #Validamos que se tenga 'check_subdirs' en el json
    if 'check_subdirs' in cms_json.keys():
        print_verbose('\nBuscando subdirectorios', opts.verbose)
        #iteramos sobre todos los subdirs dados
        for s in cms_json['check_subdirs'].keys():
            #if head(concat(cms_root, cms_json['check_subdirs'][s], True)).status_code == 200:
            print_verbose('Haciendo HEAD: '+ concat(cms_root, cms_json['check_subdirs'][s], True), opts.verbose)
            code = head(concat(cms_root, cms_json['check_subdirs'][s], True)).status_code
            if code == 200 or code == 403:
                #Existe al menos un subdirectorio dado, lo que nos dice que si es el
                #CMS esperado
                print_verbose('CMS ENCONTRADO!!!!', opts.verbose)
                print_verbose('------> CMS: ' + cms_json['cms'] + '<--------', True)
                print_report('Se encontro el CMS!!    ' + cms_json['cms'], opts.report)

                return True
        #Llegado a este punto, no hubo ninguna respuesta 200 o 403 a los recursos
        print_verbose('No se encontro coincidencia con subdirectorios dados', opts.verbose)
        print_report('No se pudo diferenciar el CMS', opts.report)

        return False
    else:
        print_verbose('No se dieron subdirectorios a buscar', opts.verbose)
        print_report('No se dieron subdirectorios a buscar', opts.report)
        return False


def check_backups(cms_root, opts):
    print "si"
    #falta


def check_version(cms_root, opts, cms_json):
    """
        Funcion que busca la version del cms a partir de los recursos
        y los patrones de busqueda dados en el json.

        Devuelve True si encuentra la version, False en caso contrario
    """
    #Revisamos que exista la llave 'check_version' en el json
    if 'check_version' in cms_json.keys():
        print_verbose("\nBuscando version del CMS", opts.verbose)

        #Iteramos si se dan varias tuplas de busqueda
        for  gv in cms_json['check_version'].keys():
            #El formato en el json es recurso;patron_de_busqueda
            resource, patron = cms_json['check_version'][gv].split(';')
            #buscamos el patron en el codigo fuente del recurso, obteniendo 20 caracteres inmediatos
            #anteriores y 30 inmediatos posteriores
            #patron_founded = search('(.{1,20}' + patron + '.{1,30})', get(concat(cms_root, resource)).text)
            print concat(cms_root, resource)
            patron_founded = search('(.{0,20}' + patron + '.{1,30})', get(concat(cms_root, resource)).text)
            if patron_founded:
                #Dentro de este string buscamos el numero de version nn.nn.nn
                version = search(patron + '.*([1-9]{1,2}\.[0-9]{1,2}\.[0-9]{1,2})', patron_founded.group(1))
                version2 = search(patron + '.*([1-9]{1,2}\.?[0-9]{0,2}\.?[0-9]{0,2})', patron_founded.group(1))
                if version:
                    print_verbose('Version encontrada!!!!', opts.verbose)
                    print_verbose("----------> Version: " + version.group(1)  + " <----------", opts.verbose)
                    print_report('Version del CMS encontrada:    ' + version.group(1), opts.report)
                    return True

                elif version2:
                    print_verbose('Version encontrada!!!!', opts.verbose)
                    print_verbose("----------> Version: " + version2.group(1)  + " <----------", opts.verbose)
                    print_report('Version del CMS encontrada:    ' + version2.group(1), opts.report)
                    return True

    else:
        printError('No se encontro la llave check_version en el json dado')
        print_report('No se asigno valor a check_version en el json dado', opts.report)

    return False


def list_user(opts, login_page, user_log, password_log, error_regex):
    """
        Funcion que hace un ataque de fuerza bruta para listar usuarios comunes
        en el login del CMS. El ataque se hace con una contrasena cualquiera, pues
        el punto no es encontrar credenciales, solo existencia de usuarios comunes.

        Retorna una lista con todos los usuarios validos encontrados se
        almacenan en una lista.

        user_log es el nombre del input para la cuenta de usuario dentro del
        formulario. password_log es el nombre del input de la contrasena dentro
        del mismo
    """
    #Lista para almacenar los usuarios validos
    valid_users = []
    try:
        with open(opts.userlist) as userlist:
            for user in userlist:
                #Quitamos el \n del final de la linea leida
                user = user[:len(user) - 1]
                #En el body ponemos los datos del formulario
                #La contrasena es indiferente
                payload = {user_log: user, password_log: 'password'}
                print_verbose('Peticion con el usuario ' + user, opts.verbose)

                r = post(login_page, data=payload)
                #Buscamos el error dado, que depende del cms encontrado
                err = search(error_regex, str(r.text))

                if err:
                    print_verbose('El usuario ' + user + ' Es un usuario valido!', opts.verbose)
                    valid_users.append(user)
                
            if len(valid_users) > 0:
                print_verbose("Usuarios validos encontrados: ", opts.verbose)
                print_report("Usuarios validos encontrados: ", opts.report)
                for usr in valid_users:
                    print_verbose("\t" + usr, opts.verbose)
                    print_report( "\t" + user, opts.report)
            else:
                print_verbose("No se encontraron usuarios validos", opts.verbose)
                print_report("No se encontraron usuarios validos", opts.report)

            return valid_users


    except IOError:
        print_report('Error al leer el archivo ' + opts.userlist, opts.report)
        printError('El archivo ' + opts.userlist + ' no existe o no se tiene permisos de lectura')


def check_login(cms_root, opts, cms_json):
    """
        Funcion que analiza existencia de usuarios validos en el login del cms
        
        Es necesario haber detectado antes el CMS

        Dependiendo del CMS detectado anteriormente, es que se analiza el
        response de la pagina ante cada intento de inicio de sesion
    """
    #establecemos que nos referimos a una variable global, no local
    global cms_detected
    global commons_cms

    if 'check_login' in cms_json.keys():
        #obtenemos la url del recurso de login
        #login_page = concat(cms_root, cms_json['check_login'])
        login_page = concat(cms_root, cms_json['check_login'])
        
        print_verbose('\nBuscando usuarios comunes en: ' + login_page +"\n", opts.verbose)
        
        if cms_detected == 'Wordpress':
            #obtenemos los valores respectivos necesarios de commmons_cms
            list_user(opts, login_page, commons_cms['Wordpress'][0], commons_cms['Wordpress'][1], commons_cms['Wordpress'][2])        

        if cms_detected == 'Joomla':
            #No hay forma de listar usuarios en Joomla sin ataque de fuerza bruta de
            #usuario-contrasena
            print_verbose("Joomla no expone informacion de las cuentas registradas", opts.verbose)
            print_report("Joomla no expone informacion de las cuentas registradas", opts.report)
    
    else:
        print_report('No existe campo check_list en el json dado', opts.report)
        printError('No existe campo check_list en el json dado')


def get_installed_plugins(opts, cms_json, cms_root):
    """
        Funcion que consulta los plugins instalados dentro del CMS
        Solo busca los n plugins instalados, n esta definida en num_plugins
        retorna la lista con los plugins instalados
    """
    #Se valida que existan estos campos en el JSON
    if 'plugins' in cms_json.keys() and 'plugins_dir' in cms_json.keys():
        #Lista donde se almacenan los plugins instalados
        installed_plugins = []
        try:
            with open(cms_json['plugins'], "r") as plugins_file:
                print_verbose('Buscando plugins instalados dentro del CMS', opts.verbose)
                print_report('\n\tPlugins:', opts.report)
                #Iteramos sobre num_plugins plugins dentro del archivo
                for x in range(opts.num_plugins):
                    #Se le quita el salto de linea
                    plugin = plugins_file.readline()[:-1]
                    #print "plugin: "+plugin
                    #Se obtiene la ruta absoluta al plugin
                    url2plugin = concat(concat(cms_root, cms_json['plugins_dir']),plugin)
                    s=session()
                    headers={}
                    headers['User-agent']=choice(make_agent('user_agents.txt'))
                    response=head(url2plugin, headers=headers)
                    #print plugin
                    #Si se obtiene respuesta 200 o 403, es que este recurso existe
                    if (response.status_code == 200 or response.status_code == 403):
                        installed_plugins.append(plugin)

                        print_verbose('El plugin '+plugin+ ' esta instalado en el CMS', opts.verbose)
                        print_report("El plugin " + plugin +" esta instalado en el CMS", opts.report)

        except IOError:
            print_report('Error al abrir el archivo dado en plugins', opts.report)
            printError('Error al intentar leer el archivo',True) 

    else:
        print_report('No se encontraron en el JSON las llaves necesarias: \n plugins y plugins_dir', opts.report)
        printError('Error en el json dado',True)




def main_cms_analizer():
    """
        Funcion principal del script
    """
    #try:
    global cms_detected
    opts = addOptions()
    create_report(opts.url, opts, opts.report)
    checkOptions(opts)
    #En este punto ya se reviso existencia de -u y -c
    cms_json = read_cmsJSON(opts)
    cms_root = get_root(opts,cms_json["check_root"])
    #cms_root = opts.url
    if check_subdirs(opts, cms_json, cms_root):
        #Se prosigue con la ejecucion si se reconocio el CMS
        cms_detected = cms_json['cms']
        
        check_version(cms_root, opts, cms_json)
        check_backups(cms_root, opts)
        get_installed_plugins(opts, cms_json, cms_root)
        #check_login(cms_root, opts, cms_json)


if __name__ == '__main__':
    main_cms_analizer()
