# CMS ANALIZER  

## Descripcion
Script que analiza aplicativos Web buscando el CMS que los maneja.

## Ejecucion
El script necesita de algunos parametros esenciales para funcionar, como la URL del aplicativo
y un archivo JSON definido para encontrar el CMS del objetivo

### Makefile
El Makefile del proyecto crea una liga suave al directorio de binarios del usuario.
Así se puede invocar el script como un comando cualquiera.
Importante correr con **privilegios sudo**.

Ejemplo:

```
  sudo make
  sudo make clean
```

### Banderas
Para sue ejecución, el script puede recibir distintos argumentos:

* _-u_ -> La URL del aplicativo objetivo.
* _-c_ -> Archivo JSON de configuracion al script
* _-v_ -> Habilita el modo verboso del script
* _-r_ -> Nombre del archivo de salida del reporte final creado
* _-U_ -> User-Agent o archivo con User-Agents a usar para las consultas HTTP
* _-w_ -> Lista de nombres de usuarios a buscar en el login del CMS
* _-C_ -> Lista de archivos comunes existentes a buscar en la raiz del aplicativo
* _-n_ -> Numero de plugins y temas a buscar dentro del CMS  (iteraciones en el archivo correspondiente)
* _-p_ -> Archivo de contraseñas a probar en el login del CMS

Las banderas esenciales para que el script funcione son **-u** y **-c**.
Las demas banderas tienen un valor por defecto que se usa en caso de no especificarse.

### Ejecución de la herramienta
Una vez hecho el Makefile, se ejecuta de la siguiente manera
```
cms_analizer -u <URL_del_aplicativo_objetivo> -c <archivo_JSON_de_configuracion> [opciones] 
```

## Archivos de configuracion
Estos archivos JSON sirven para configurar la herramienta para un cierto CMS deseado.
Poseen varias llaves definidas necesarias:
* cms -> Define el nombre del CMS que describe el archivo
* check_subdirs -> Define directorios en la raiz para reconocer el CMS
* check_files -> Archivos con informacion sensible del CMS
* check_version -> Define el recurso y el patron a buscar para encontrar la version del CMS 
                  "/ruta/al/recurso;patron_a_buscar_en_el_source_page"
* check_login -> Ruta relativa al inicio de sesión del CMS (para listar los usuarios)
* check_root -> Archivos comunes en la raiz del CMS (para identificar la raiz en la URL dada)
* plugins_dir -> La ruta relativa donde se almacenan los plugins dentro del CMS
* plugins -> Archivo donde se almacenan los plugins populares del CMS
* themes_dir -> La ruta relativa donde se almacenan los temas dentro del CMS
* themes -> Archivo donde se almacenan los temas populares del CMS

