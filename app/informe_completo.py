from ctypes import windll
from datetime import datetime
from string import ascii_uppercase
import pythoncom
import subprocess
import os
import threading
import winreg

import win32com

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
            h1 { font-family: "Courier New", monospace; }

        </style>
    </head>
    <body>
    <h1>LISTADO DE USUARIOS</h1>

    '''
       
    if salida:
        html_content += '<pre>' + salida + '</pre>'
        
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
    html_content = f'''
    <html>
    <head>
        <title>Particiones</title>
        <!-- Enlace al CSS de Bootstrap -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
        <style>
            /* Estilos adicionales específicos */
            pre {{
                font-family: "Courier New", monospace;
                white-space: pre-wrap; /* Mantiene los saltos de línea y espacios en blanco */
                word-wrap: break-word; /* Permite que el texto se ajuste en líneas más cortas */
                padding: 1em;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #f8f9fa; /* Color de fondo suave */
            }}
            h1 {{font-family: "Courier New", monospace; }}
        </style>
    </head>
    <body>
    <h1>PARTICIONES</h1>
    <pre>{texto_resultados}</pre>
    </body>
    </html>'''
    
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
    <!DOCTYPE html>
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
            h1 { font-family: "Courier New", monospace; }
        </style>
    </head>
    <body>
    <h1>INFORMACIÓN DEL S.O</h1>

    '''
    
    if salida:
        html_content += '<pre>' + salida + '</pre>'
        
    if errores:
        html_content += '<h1>ERRORES</h1><pre>' + errores + '</pre>'
        
    html_content += '</body></html>'
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(output_dir, 'info_so.html'), 'w', encoding='utf-8') as file:
        file.write(html_content)


#######################################################################################

def generar_indice_html():
    unidades = obtener_unidades_disco()
    
    # Generar el contenido HTML del índice
    html_content = '''
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Índice</title>
        <style>
            body { font-family: "Courier New", monospace; }
            h1 { font-family: "Courier New", monospace; }
        </style>
        <!-- Enlace al CSS de Bootstrap -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <h1>Índice de Resultados</h1>
        <ul>
            <li><a href="listar_usuarios.html">Listar Usuarios</a></li>
            <li><a href="particiones.html">Particiones</a></li>
            <li><a href="info_so.html">Información del Sistema Operativo</a></li>
            <li><a href="maquinas_virtuales.html">Máquinas Virtuales del sistema</a></li>
            <li><a href="mostrar_usb.html">Listado de dispositivos USBs alguna vez conectados</a></li>
            <li><a href="resultado_wifi.html">Listado de Redes</a></li>
            <li><a href="listado_software.html">Software Instalado</a></li>
            <li><a href="papelera.html">Información de la Papelera</a></li>
            <li>Los árboles de directorios han sido cargados en la carpeta "trees/autoReport", a la misma altura que el ejecutable.</li>
            <li><a href="carpetas_sincro.html">Carpetas sincronizadas</a></li>
            <li>Por razones de rendimiento, los hashes han sido guardados en los archivos:
    '''
    for i, unidad in enumerate(unidades):
        unidad = unidad.strip(":")
        html_content += f"hashes_{unidad}.txt"
        if i < len(unidades) - 1:
            html_content += ", "
        
    html_content +=  "</li>"
        
    
    html_content += '''
        </ul>
    </body>
    </html>
    '''
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(output_dir, 'indice.html'), 'w', encoding='utf-8') as file:
        file.write(html_content)

#######################################################################################

def buscar_en_registro(clave_registro, nombre_valor):
    """
    Busca la ruta del ejecutable en el registro de Windows.
    """
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, clave_registro) as clave:
            ruta_instalacion = winreg.QueryValueEx(clave, nombre_valor)[0]
            return ruta_instalacion
    except FileNotFoundError:
        print(f"Clave de registro {clave_registro} no encontrada.")
        return None
    except OSError as e:
        print(f"Error al acceder al registro: {e}")
        return None

def encontrar_vboxmanage_path():
    """
    Busca vboxmanage.exe en el registro de Windows.
    """
    clave_registro = r"SOFTWARE\Oracle\VirtualBox"
    nombre_valor = "InstallDir"
    ruta_instalacion = buscar_en_registro(clave_registro, nombre_valor)
    if ruta_instalacion:
        ruta_archivo = os.path.join(ruta_instalacion, 'vboxmanage.exe')
        if os.path.isfile(ruta_archivo):
            return ruta_archivo
        else:
            print(f"Archivo vboxmanage.exe no encontrado en {ruta_instalacion}")
    return None

def encontrar_vmrun_path():
    """
    Busca vmrun.exe en el registro de Windows.
    """
    claves_registro = [
        r"SOFTWARE\VMware, Inc.\VMware Workstation",
        r"SOFTWARE\WOW6432Node\VMware, Inc.\VMware Workstation"
    ]
    nombre_valor = "InstallPath"
    
    for clave_registro in claves_registro:
        ruta_instalacion = buscar_en_registro(clave_registro, nombre_valor)
        if ruta_instalacion:
            ruta_archivo = os.path.join(ruta_instalacion, 'vmrun.exe')
            if os.path.isfile(ruta_archivo):
                return ruta_archivo
            else:
                print(f"Archivo vmrun.exe no encontrado en {ruta_instalacion}")
    
    return None

def obtener_maquinas_virtuales_virtualbox():
    """
    Obtiene la lista de máquinas virtuales de VirtualBox.
    """
    try:
        vboxmanage_path = encontrar_vboxmanage_path()
        if not vboxmanage_path:
            return "VirtualBox no se encontró en el sistema."
        resultado = subprocess.check_output([vboxmanage_path, 'list', 'vms']).decode('utf-8')
        return resultado.strip() if resultado.strip() else "No hay máquinas virtuales en VirtualBox."
    except subprocess.CalledProcessError as e:
        return f"Error al obtener la lista de máquinas virtuales de VirtualBox: {e}"

def find_vmx_files():
    
    # Directorios comunes donde las máquinas virtuales suelen almacenarse
    directories = [
        os.path.join(os.path.expanduser("~"), "Documents", "Virtual Machines"),
        os.path.join(os.path.expanduser("~"), "Documentos", "Virtual Machines"),
        os.path.join(os.path.expanduser("~"), "OneDrive", "Documentos", "Virtual Machines"),
        os.path.join(os.path.expanduser("~"), "OneDrive", "Documents", "Virtual Machines"),
        "C:\\Users\\Public\\Documents\\Shared Virtual Machines\\"
    ]
    
    vmx_files = []
    for directory in directories:
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith(".vmx"):
                    vmx_files.append(os.path.join(root, file))
                    
    return vmx_files

def mostrar_maquinas_virtuales():
    # Obtiene la lista de máquinas virtuales de cada sistema
    salida_vbox = obtener_maquinas_virtuales_virtualbox()
    salida_vmware = find_vmx_files()
    salida_vmware_str = '\n'.join(salida_vmware)

    # Generar la salida en HTML
    html_output = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Máquinas Virtuales</title>
        <style>
            pre {{
                font-family: "Courier New", Courier, monospace;
                background-color: #f4f4f4;
                padding: 10px;
                border: 1px solid #ddd;
                overflow: auto;
            }}
            h1 {{ font-family: "Courier New", monospace; }}
            h2 {{ font-family: "Courier New", monospace; }}


        </style>
        <!-- Enlace al CSS de Bootstrap -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <h1>Resultado de la Búsqueda de Máquinas Virtuales</h1>
        <h2>VirtualBox</h2>
        <pre>{}</pre>
        <hr>
        <h2>VMware</h2>
        <pre>{}</pre>
    </body>
    </html>
    """.format(salida_vbox, "No se ha encontrado máquinas VMWare." if not salida_vmware else salida_vmware_str)

    # Guardar la salida en un archivo HTML
    with open(os.path.join(output_dir,"maquinas_virtuales.html"), "w", encoding="utf-8") as file:
        file.write(html_output)
        
#######################################################################################

def get_usb_devices():
    usb_devices = []
    reg_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    
    try:
        reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
        
        for i in range(winreg.QueryInfoKey(reg_key)[0]):
            vendor_product_key = winreg.EnumKey(reg_key, i)
            device_key_path = f"{reg_path}\\{vendor_product_key}"
            device_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_key_path)
            
            for j in range(winreg.QueryInfoKey(device_key)[0]):
                serial_key = winreg.EnumKey(device_key, j)
                serial_key_path = f"{device_key_path}\\{serial_key}"
                serial_key_opened = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, serial_key_path)
                
                device_info = {}
                try:
                    device_info['Vendor_Product'] = vendor_product_key
                    device_info['Serial'] = serial_key
                    device_info['FriendlyName'] = winreg.QueryValueEx(serial_key_opened, 'FriendlyName')[0]
                except FileNotFoundError:
                    device_info['FriendlyName'] = 'Unknown'

                usb_devices.append(device_info)
                
                winreg.CloseKey(serial_key_opened)
                
            winreg.CloseKey(device_key)
        
        winreg.CloseKey(reg_key)
    except WindowsError as e:
        print(f"An error occurred accessing the registry: {e}")
    
    return usb_devices

def mostrar_usbs():
    # Obtiene la lista de dispositivos USB
    dispositivos = get_usb_devices()
    salida_str = '\n'.join(f"Serial: {d['Serial']}, FriendlyName: {d['FriendlyName']}" + "\n" for d in dispositivos)

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Historial de Dispositivos USBs</title>
        <style>
            pre {{
                font-family: "Courier New", Courier, monospace;
                background-color: #f4f4f4;
                padding: 10px;
                border: 1px solid #ddd;
                overflow: auto;
            }}
            h1 {{ font-family: "Courier New", monospace; }}
        </style>
        <!-- Enlace al CSS de Bootstrap -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <h1>Dispositivos USB Conectados</h1>
        <pre>{ "No se ha conectado ningún dispositivo USB aún." if not dispositivos else salida_str }</pre>
    </body>
    </html>
    """

    # Guardar la salida en un archivo HTML
    with open(os.path.join(output_dir, "mostrar_usb.html"), "w", encoding="utf-8") as file:
        file.write(html_content)
        
#######################################################################################
        
import subprocess

def mostrar_perfiles_wifi():
    
    # Crear HTML base
    salida_formateada = '''
    <html>
    <head>
        <title>Historial de Redes</title>
        <style>
            pre { background-color: #f4f4f4; padding: 10px; border: 1px solid #ddd; overflow: auto; }
            body { font-family: Courier New, monospace; }
            .encabezado { font-size: 20px; font-weight: bold; }
            .detalle { font-size: 12px; font-family: Courier New, monospace; }
        </style>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
    <h1>HISTORIAL DE REDES</h1>
    '''
    
    # Ejecuta el comando y obtiene la salida
    try:
        servicio_estado = subprocess.check_output(['sc', 'query', 'wlansvc'], text=True)
        if "RUNNING" not in servicio_estado:
            salida_formateada += "<pre>El servicio 'wlansvc' no está en ejecución.</pre>"
            guardar_resultado_html(salida_formateada + '</body></html>')
            return None
        else:
            try:
                resultado = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], text=True)
                if "Perfil de todos los usuarios" not in resultado or "No hay ninguna interfaz inalámbrica en el sistema." in resultado:
                    resultado = "No se ha conectado a ninguna red WiFi aún."
                    perfiles = None
            except subprocess.CalledProcessError as e:
                resultado = f"Error al ejecutar el comando: {e}"
                salida_formateada = f'-------\nSALIDA|\n-------\n{resultado}'
                guardar_resultado_html(salida_formateada)
                return

    except subprocess.CalledProcessError as e:
        guardar_resultado_html(f"Error al verificar el estado del servicio 'wlansvc': {e}")
        return None

    # Procesar la salida para formatearla
    lineas = resultado.splitlines()
    perfiles = []
    dentro_perfiles_usuario = False

    for linea in lineas:
        if "Perfiles de usuario" in linea:
            dentro_perfiles_usuario = True
            continue
        if dentro_perfiles_usuario and "Perfil de todos los usuarios" in linea:
            perfil = linea.split(':', 1)[-1].strip()
            perfiles.append(perfil)

    # Añadir perfiles y si no hay, muestro mensaje
    if perfiles:
        for idx, perfil in enumerate(perfiles, start=1):
            try:
                # Obtener información detallada del perfil
                detalle = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', f'name={perfil}', 'key=clear'], text=True)
            except subprocess.CalledProcessError as e:
                detalle = f"Error al obtener detalles para {perfil}: {e}"

            # Añadir el perfil y su detalle a la salida
            salida_formateada += f'<p class="encabezado">=== Red WiFi {idx}: {perfil} ===</p>'
            salida_formateada += '<pre class="detalle">'
            salida_formateada += detalle
            salida_formateada += '</pre>'
    else:
        salida_formateada += '<p>No se ha conectado a ninguna red WiFi aún.</p>'        

    # Cerrar HTML
    salida_formateada += '</body></html>'

    # Guardar el resultado en un archivo HTML
    guardar_resultado_html(salida_formateada)

def guardar_resultado_html(contenido):
    ruta_archivo = os.path.join(output_dir, 'resultado_wifi.html')
    
    try:
        with open(ruta_archivo, 'w', encoding='utf-8') as archivo:
            archivo.write(contenido)
    except IOError as e:
        print(f"Error al guardar el archivo: {e}")
        
####################################################################################### 
        
def listado_software():
    
    comando = [
        'powershell.exe',
        '-Command',
        "Get-Package | Where-Object { $_.ProviderName -ne 'msu' } | Select-Object Name, Version, ProviderName"
    ]    
    
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
        <title>Listado Software</title>
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
            h1 { font-family: "Courier New", monospace; }
        </style>
    </head>
    <body>
    <h1>LISTADO SOFTWARE</h1>
     
    '''
       
    if salida:
        html_content += '<pre>' + salida + '</pre>'
        
    if errores:
        html_content += '<pre>' + errores + '</pre>'
        
    html_content += '</body></html>'
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(output_dir, 'listado_software.html'), 'w', encoding='utf-8') as file:
        file.write(html_content)
        
#######################################################################################       
        
def obtener_informacion_papelera():
    
    pythoncom.CoInitialize()

    try:
        shell = win32com.client.Dispatch("Shell.Application")
        reciclaje = shell.Namespace("shell:::{645FF040-5081-101B-9F08-00AA002F954E}")

        if reciclaje is None:
            print("No se pudo acceder a la Papelera de Reciclaje.")
            return None

        items = reciclaje.Items()
        resultados = []

        for item in items:
            nombre = item.Name
            tipo = item.Type
            tamaño = item.ExtendedProperty('Size')
            fecha_borrado = item.ExtendedProperty('DateDeleted')

            resultados.append({
                "Nombre": nombre,
                "Tipo": tipo,
                "Tamaño": f"{tamaño} bytes" if tamaño else "Desconocido",
                "Fecha de Eliminación": fecha_borrado if fecha_borrado else "Desconocida"
            })

        return resultados
    finally:
        # Desinicializar COM
        pythoncom.CoUninitialize()

                
def mostrar_informacion_papelera():
    resultados = obtener_informacion_papelera()
    
    # Crear el contenido HTML
    html_content = '''
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Listado de Papelera de Reciclaje</title>
        <!-- Enlace al CSS de Bootstrap -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
        <style>
            /* Estilos adicionales específicos */
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
                font-size: 16px;
                text-align: left;
            }}
            th, td {{
                border: 1px solid #ddd;
                padding: 8px;
            }}
            th {{
                background-color: #f4f4f4;
                font-weight: bold;
            }}
            tr:nth-child(even) {{
                background-color: #f9f9f9;
            }}
            tr:hover {{
                background-color: #f1f1f1;
            }}
            h1 { font-family: "Courier New", monospace; }
            td { font-family: "Courier New", monospace; }

        </style>
    </head>
    <body>
    <div class="container">
        <h1 class="my-4">Información de la Papelera de Reciclaje</h1>
        <table class="table table-bordered">
            <thead>
                <tr>
                    <th>NOMBRE</th>
                    <th>TIPO</th>
                    <th>TAMAÑO</th>
                    <th>ELIMINACIÓN</th>
                </tr>
            </thead>
            <tbody>
    '''
    
    if len(resultados) == 0:
        html_content += "<p> No hay elementos en la papelera. </p>"
    else:
        for item in resultados:
            html_content += '<tr>'
            html_content += f'<td>{item.get("Nombre", "Desconocido")}</td>'
            html_content += f'<td>{item.get("Tipo", "Desconocido")}</td>'
            html_content += f'<td>{item.get("Tamaño", "Desconocido")}</td>'
            html_content += f'<td>{item.get("Fecha de Eliminación", "Desconocida")}</td>'
            html_content += '</tr>'
    
    html_content += '''
            </tbody>
        </table>
    </div>
    </body>
    </html>
    '''
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(output_dir, 'papelera.html'), 'w', encoding='utf-8') as file:
        file.write(html_content)

#######################################################################################

def obtener_unidades_disco():
    # Obtiene una lista de todas las unidades de disco disponibles
    unidades = []
    result = subprocess.run(['wmic', 'logicaldisk', 'get', 'name'], capture_output=True, text=True)
    if result.returncode == 0:
        # Se divide la salida en líneas y se omite la primera línea (encabezado)
        lineas = result.stdout.splitlines()
        if len(lineas) > 1:
            unidades = [line.strip() for line in lineas[1:] if line.strip()]
    return unidades

def limpiar_nombre_archivo(nombre):
    # Reemplaza caracteres no válidos en nombres de archivo
    return nombre.replace(":", "").replace("\\", "_").replace("/", "_").replace(" ", "_")

def generar_html_contenido2(estructura_directorio):
    # Convierte la estructura del directorio en formato HTML
    html_content = "<html><head><title>Estructura del Directorio</title></head><body>"
    html_content += "<pre>{}</pre>".format(estructura_directorio)
    html_content += "</body></html>"
    return html_content

def ejecutar_comando(unidad, archivo_salida):
    # Ejecuta el comando para la unidad dada y captura la salida
    comando = [
        'powershell.exe',
        '-Command',
        f"tree /A {unidad}// | Out-String"
    ]
    
    resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
    
    # Genera el contenido HTML a partir de la salida del comando
    if resultado.returncode == 0:
        contenido_html = generar_html_contenido2(resultado.stdout)
        # Asegúrate de que el directorio ./trees/ exista
        os.makedirs('./trees/autoReport', exist_ok=True)
        with open(f'./trees/autoReport/{archivo_salida}', 'w') as archivo_html:
            archivo_html.write(contenido_html)
        print(f'Diagrama generado en: /trees/{archivo_salida}')
    else:
        print(f'Error al generar diagrama para {unidad}')

def iniciar_comando(unidad):
    # Mensaje de aviso en la consola
    print("Por favor, espere a que se genere el diagrama de todas las unidades mostradas. Dependiendo del volumen de archivos, algunas pueden tardar más que otras.")
    print("NO SELECCIONE OTRO PROCESO HASTA QUE TERMINE ESTE\n")


    archivo_salida = f'directory_tree_{limpiar_nombre_archivo(unidad)}.html'
    threading.Thread(target=ejecutar_comando(unidad, archivo_salida)).start()

#######################################################################################

def get_onedrive_path():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\OneDrive")
        onedrive_path, _ = winreg.QueryValueEx(key, "UserFolder")
        return onedrive_path
    except FileNotFoundError:
        return None

def get_synced_folders(onedrive_path):
    synced_folders = []
    if onedrive_path:
        for root, dirs, files in os.walk(onedrive_path):
            for folder in dirs:
                folder_path = os.path.join(root, folder)
                synced_folders.append(folder_path)
            #break  # No necesitamos recorrer subcarpetas recursivamente
    return synced_folders

def generar_html_contenido(onedrive_path, synced_folders):
    # Plantilla básica HTML
    html_template = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Carpetas Sincronizadas</title>
        <!-- Enlace al CSS de Bootstrap -->
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
        <style>
            /* Estilos adicionales específicos */
            pre {{
                font-family: "Courier New", monospace;
                white-space: pre-wrap; /* Mantiene los saltos de línea y espacios en blanco */
                word-wrap: break-word; /* Permite que el texto se ajuste en líneas más cortas */
                padding: 1em;
                border: 1px solid #ccc;
                border-radius: 4px;
                background-color: #f8f9fa; /* Color de fondo suave */
            }}
            h1 {{ font-family: "Courier New", monospace; }}
            li {{ font-family: "Courier New", monospace; }}

        </style>
    </head>
    <body>
    <h1>CARPETAS SINCRONIZADAS CON ONEDRIVE</h1>
    {contenido}
    </body>
    </html>
    """
    
    if onedrive_path:
        contenido = f"<p>OneDrive está sincronizado en: {onedrive_path}</p>\n"
        for folder in synced_folders:
            contenido += f"<li>{folder}</li>\n"
        contenido += "</ul>\n"
    else:
        contenido = "<p>OneDrive no está configurado en este equipo.</p>\n"
    
    # Insertar el contenido generado en la plantilla
    html_content = html_template.format(contenido=contenido)

    with open(os.path.join(output_dir, 'carpetas_sincro.html'), 'w', encoding='utf-8') as file:
        file.write(html_content)

def mostrar_carpetas_sin():
    onedrive_path = get_onedrive_path()
    synced_folders = get_synced_folders(onedrive_path)
    generar_html_contenido(onedrive_path, synced_folders)
    
#######################################################################################

import os
import hashlib
import concurrent.futures
import time
import informe_completo  # Importa el módulo time para medir el tiempo

def listar_archivos(directorio, extensiones_excluidas):
    """
    Lista todos los archivos en el directorio y subdirectorios, excluyendo ciertos tipos de archivos.

    Args:
        directorio (str): El directorio raíz desde donde empezar la búsqueda.
        extensiones_excluidas (list): Lista de extensiones de archivos a excluir (por ejemplo, ['.tmp', '.bak']).

    Returns:
        list: Una lista de rutas completas de archivos.
    """
    if extensiones_excluidas is None:
        extensiones_excluidas = ['.tmp', '.bak', '.swp', '.swo', '.dll', '.sys']

    archivos = []

    for root, dirs, files in os.walk(directorio):
        print(f"Buscando en: {root}")  # Imprime el directorio actual que se está buscando
        for file in files:
            if not any(file.endswith(ext) for ext in extensiones_excluidas):
                ruta_completa = os.path.join(root, file)
                archivos.append(ruta_completa)

    return archivos

# Obtener unidades de disco
unidades = informe_completo.obtener_unidades_disco()

print("Unidades de disco:", unidades)  # Imprime las unidades que se obtienen

def calcular_hash_archivo(ruta_archivo, algoritmo='md5'):
    """
    Calcula el hash de un archivo.

    Args:
        ruta_archivo (str): La ruta del archivo.
        algoritmo (str): El algoritmo de hash a utilizar (por defecto 'md5').

    Returns:
        str: El hash del archivo en formato hexadecimal.
    """
    # Crea un objeto hash del tipo especificado
    try:
        # Crea un objeto hash del tipo especificado
        hash_obj = hashlib.new(algoritmo)

        # Lee el archivo en bloques para no cargarlo todo en memoria a la vez
        with open(ruta_archivo, 'rb') as archivo:
            while chunk := archivo.read(1048576):  # Leer en bloques de 1MB
                hash_obj.update(chunk)

        # Devuelve el hash en formato hexadecimal
        return hash_obj.hexdigest()

    except PermissionError as pe:
        print(f"Permiso denegado para leer el archivo: {ruta_archivo}. Error: {pe}")
        return None
    except OSError as e:
        if e.errno == 32:  # ERROR_SHARING_VIOLATION
            print(f"El archivo está siendo utilizado por otro proceso: {ruta_archivo}")
        elif (e.errno == 22):
            print(f"No se puede acceder a dicho archivo ya que es de permisos reservados del sistema {ruta_archivo}")
        else:
            print(f"Error al acceder al archivo: {ruta_archivo}. Error: {e}")
        return None

extensiones_temporales = ['.tmp', '.bak', '.swp', '.swo', '.dll', '.sys']

def generar_doc_hashes():
    for unidad in unidades:
        directorio = f'{unidad}\\'

        # Listar archivos excluyendo temporales
        archivos = listar_archivos(directorio, extensiones_excluidas=extensiones_temporales)
        
        print(f"Archivos encontrados en {directorio}: {archivos}")  # Imprime la lista de archivos encontrados

        unidad_para_txt = unidad.strip(":")
        # Guardar el listado en un archivo de texto
        with open(f'listado_archivos_{unidad_para_txt}.txt', 'w', encoding='utf-8') as f:
            for archivo in archivos:
                f.write(f"{archivo}\n")

        # Ahora calculamos y guardamos los hashes
        with open(f'listado_archivos_{unidad_para_txt}.txt', 'r', encoding='utf-8') as archivo_listado:
            with open(f'hashes_{unidad_para_txt}.txt', 'w', encoding='utf-8') as hash_file:
                for linea in archivo_listado:
                    # Elimina caracteres de nueva línea y espacios en blanco
                    ruta_archivo = linea.strip()
                    if os.path.isfile(ruta_archivo):  # Verifica si el archivo existe
                        try:
                            hash_value = calcular_hash_archivo(ruta_archivo, 'md5')
                            hash_file.write(f"{ruta_archivo}: {hash_value}\n")
                        except PermissionError as pe:
                            print(f"Permiso denegado para leer el archivo: {ruta_archivo}: {pe}")
                        except Exception as e:
                            print(f"Error al calcular el hash para {ruta_archivo}: {e}")
                            
                        '''
                        hash_value = calcular_hash_archivo(ruta_archivo, 'md5')
                        if hash_value:  # Solo escribe si el hash no está vacío
                            hash_file.write(f"{ruta_archivo}: {hash_value}\n")
                        '''