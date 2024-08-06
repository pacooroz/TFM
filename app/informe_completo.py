import subprocess
import os

# Crear la carpeta si no existe
output_dir = 'GeneratedReport'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
    
def listar_usuarios_html():
    comando = 'powershell.exe -Command "Get-LocalUser | Select-Object Name, FullName, Description, Enabled, PasswordChangeableDate, PasswordExpires, PasswordLastSet, LastLogon, UserMayChangePassword, PrincipalSource"'
    
    resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
    
    salida = resultado.stdout.strip()
    errores = resultado.stderr.strip()
    
    # Generar el contenido HTML
    html_content = '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Lista de Usuarios</title>
        <!-- Enlace al CSS de Bootstrap -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
        <style>
            /* Estilos adicionales específicos */
            pre {
                font-family: "Courier New", monospace;
                white-space: pre-wrap; /* Mantiene los saltos de línea y espacios en blanco */
                word-wrap: break-word; /* Permite que el texto se ajuste en líneas más cortas */
                padding: 1em;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #f8f9fa; /* Color de fondo suave */
            }
        </style>
    </head>
    <body>
            
    '''
       
    if salida:
        html_content += '<h1>SALIDA</h1><pre>' + salida + '</pre>'
        
    if errores:
        html_content += '<h1>ERRORES</h1><pre>' + errores + '</pre>'
        
    html_content += '</body></html>'
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(output_dir, 'listar_usuarios.html'), 'w', encoding='utf-8') as file:
        file.write(html_content)

#######################################################################################

import psutil

def particiones_html():
    # Obtener la lista de particiones
    particiones = psutil.disk_partitions()
    
    resultados = []
    
    for particion in particiones:
        # Obtener la información del volumen para cada partición
        info = psutil.disk_usage(particion.mountpoint)
        
        # Convertir bytes a GB con 2 decimales
        total_size_gb = info.total / (1024**3)
        used_gb = info.used / (1024**3)
        free_gb = info.free / (1024**3)
        
        resultados.append(
            f"<h2>Device: {particion.device}</h2>\n"
            f"<p>Mountpoint: {particion.mountpoint}</p>\n"
            f"<p>FileSystemType: {particion.fstype}</p>\n"
            f"<p>TotalSize: {total_size_gb:.2f} GB</p>\n"
            f"<p>Used: {used_gb:.2f} GB</p>\n"
            f"<p>Free: {free_gb:.2f} GB</p>\n"
            f"<p>PercentUsed: {info.percent:.1f}%</p>\n"
            f"<hr/>\n"  # Separador entre particiones
        )
    
    # Unir todos los resultados en un solo texto HTML
    texto_resultados = ''.join(resultados)
    
    # Generar el contenido HTML
    html_content = f'<html><head><title>Particiones</title></head><body>{texto_resultados}</body></html>'
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(output_dir, 'particiones.html'), 'w') as file:
        file.write(html_content)

#######################################################################################

def información_SO():
    comando = 'systeminfo | findstr /C:"Nombre de host" /C:"Nombre del sistema operativo" /C:"Versión del sistema operativo" /C:"Fabricante del sistema operativo" /C:"Configuración del sistema operativo" /C:"Tipo de compilación del sistema operativo" /C:"Propiedad de" /C:"Fecha de instalación original" /C:"Fabricante del sistema" /C:"Id. del producto" /C:"Modelo el sistema" /C:"Tipo de sistema" /C:"Configuración regional del sistema" /C:"Zona horaria" /C:"Dominio" /C:"Revisión(es)" /C:"Dispositivo de arranque" /C:"Versión del BIOS"'
    
    resultado = subprocess.run(comando, shell=True, capture_output=True, text=True, encoding='latin1')
    
    salida = resultado.stdout.strip()
    errores = resultado.stderr.strip()
    
    # Generar el contenido HTML
    html_content = '''
    <<!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Información del SO</title>
        <!-- Enlace al CSS de Bootstrap -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
        <style>
            /* Estilos adicionales específicos */
            pre {
                font-family: "Courier New", monospace;
                white-space: pre-wrap; /* Mantiene los saltos de línea y espacios en blanco */
                word-wrap: break-word; /* Permite que el texto se ajuste en líneas más cortas */
                padding: 1em;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #f8f9fa; /* Color de fondo suave */
            }
        </style>
    </head>
    <body>
    
    '''
    
    if salida:
        html_content += '<h1>SALIDA</h1><pre>' + salida + '</pre>'
        
    if errores:
        html_content += '<h1>ERRORES</h1><pre>' + errores + '</pre>'
        
    html_content += '</body></html>'
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(output_dir, 'info_so.html'), 'w', encoding='utf-8') as file:
        file.write(html_content)


#######################################################################################

def generar_indice_html():
    # Generar el contenido HTML del índice
    html_content = '''
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Índice</title>
        <style>
            body { font-family: "Courier New", monospace; }
        </style>
    </head>
    <body>
        <h1>Índice de Resultados</h1>
        <ul>
            <li><a href="listar_usuarios.html">Listar Usuarios</a></li>
            <li><a href="particiones.html">Particiones</a></li>
            <li><a href="info_so.html">Información del Sistema Operativo</a></li>
        </ul>
    </body>
    </html>
    '''
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(output_dir, 'indice.html'), 'w', encoding='utf-8') as file:
        file.write(html_content)
