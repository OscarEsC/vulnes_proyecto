# CMS ANALIZER  
Espinosa Curiel Oscar  
Manzano Cruz Isaias Abraham  
## Dependencias
### IMPORTANTE
### Requiere BeautifulSoup
### pip install BeautifulSoup  

## Como correrlo  
### python cms_analizer.py -u http(s)://(ip|nombre_dominio):puerto(/directorio)/ -c common.json [-v]  
-u especifica la url
-c el archivo de configuracion del script en formato JSON
-v modo verboso  

Al final de la ejecución se crearan dos archivos uno de reporte y otro con errores 4XX el importante es el de reporte ya que ahi se encuentran los hallazgos, el otro es por curiosidad  
