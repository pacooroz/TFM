from tkinter import *
import subprocess
from tkinter import font
from PIL import ImageTk, Image

#etiqueta = Label(root, text="Este es el primer paso de mi TFM")
#etiqueta.pack()

##### FRAME o MARCO#####
# Sirve como contenedor de otros Widgets
'''
marcoPrincipal = Frame()
marcoPrincipal.pack()

marcoPrincipal.config(width="800", height="600") #El tamaño no es de la ventana, si no del marco, que le dice a la ventana que ensanche
marcoPrincipal.config(bg="gray")

'''

##### Botón #####
# padx=100, pady=100 -> Tamaño
# state=DISABLED
'''
boton1 = Button(root, text="No presiones el botón", bg="blue", state=DISABLED)
boton1.pack()
'''
'''
def click_boton():
    etiqueta = Label(root, text="Este es el primer paso de mi TFM")
    etiqueta.grid(row=0, column=0)
    
boton1 = Button(root, text="No presiones el botón", bg="gray",command=click_boton)
boton1.grid(row=1, column=0)
'''
root = Tk()
root.title("INFORENSIC")
root.configure(bg="#f0f0f0")  # Fondo de la ventana

icono = PhotoImage(file="./app/static/icono.png")
root.iconphoto(True, icono)

# Establece el tamaño mínimo de la ventana
root.minsize(width=1180, height=700)

#######################################################################################
def create_window():
    global resultado_text_widget, directorio_entry # Definir el widget de texto globalmente para actualizarlo en listar_usuarios()

    root.grid_rowconfigure(0, weight=1)
    root.grid_rowconfigure(1, weight=1)
    root.grid_columnconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=3)  # Hacer la segunda columna más amplia

    # Crear el primer frame (primera columna con 3 filas)
    frame1 = Frame(root, bg="#f0f0f0")
    frame1.grid(row=0, column=0, rowspan=11, padx=10, pady=10, sticky='nsew')

    for i in range(11):
        frame1.grid_rowconfigure(i, weight=1)
    frame1.grid_columnconfigure(0, weight=1)
    
    logo = PhotoImage(file="./app/static/logo.png")
    logo_img = Label(frame1, image=logo)
    logo_img.grid(row=0, column=0, sticky='nsew')
    
    boton1 = Button(frame1, text="Listar usuarios", bg="#007bff", fg="#ffffff", command=listar_usuarios)
    boton1.grid(row=1, column=0, padx=5, pady=5, sticky='nsew')
    
    boton2 = Button(frame1, text="Particiones", bg="#007bff", fg="#ffffff", command=particiones)
    boton2.grid(row=3, column=0, padx=5, pady=5, sticky='nsew')
    
    boton4 = Button(frame1, text="Detalles S.O", bg="#007bff", fg="#ffffff", command=información_SO)
    boton4.grid(row=4, column=0, padx=5, pady=5, sticky='nsew')
    
    boton5 = Button(frame1, text="Obtener Máquinas Virtuales", bg="#007bff", fg="#ffffff", command=mostrar_maquinas_virtuales)
    boton5.grid(row=5, column=0, padx=5, pady=5, sticky='nsew')
    
    boton6 = Button(frame1, text="Obtener USBs", bg="#007bff", fg="#ffffff", command=mostrar_usbs)
    boton6.grid(row=6, column=0, padx=5, pady=5, sticky='nsew')
    
    boton7 = Button(frame1, text="Obtener Redes", bg="#007bff", fg="#ffffff", command=mostrar_perfiles_wifi)
    boton7.grid(row=7, column=0, padx=5, pady=5, sticky='nsew')
    
    boton8 = Button(frame1, text="Obtener Listado Software", bg="#007bff", fg="#ffffff", command=mostrar_listado_software)
    boton8.grid(row=8, column=0, padx=5, pady=5, sticky='nsew')
    
    boton9 = Button(frame1, text="Papelera", bg="#007bff", fg="#ffffff", command=mostrar_informacion_papelera)
    boton9.grid(row=9, column=0, padx=5, pady=5, sticky='nsew')
    
    boton10 = Button(frame1, text="Mostrar directorio", bg="#007bff", fg="#ffffff", command=iniciar_comando)
    boton10.grid(row=10, column=0, padx=5, pady=5, sticky='nsew')
    
    boton11 = Button(frame1, text="Mostrar carpetas sincronizadas", bg="#007bff", fg="#ffffff", command=mostrar_carpetas_sincronizadas)
    boton11.grid(row=11, column=0, padx=5, pady=5, sticky='nsew')
    
    # Crear el frame con fondo de color alrededor del botón y el input
    frame_calculo_hashes = Frame(frame1, bg="#ffcccc", borderwidth=2, relief="groove")
    frame_calculo_hashes.grid(row=2, column=0, padx=5, pady=5, sticky='nsew')
        
    frame_calculo_hashes.grid_rowconfigure(0, weight=1)
    frame_calculo_hashes.grid_rowconfigure(1, weight=1)
    frame_calculo_hashes.grid_rowconfigure(2, weight=1)
    frame_calculo_hashes.grid_columnconfigure(0, weight=1)
    
    boton3 = Button(frame_calculo_hashes, text="Calcular Hashes", bg="#007bff", fg="#ffffff", command=calcular_hashes_gui)
    boton3.grid(row=0, column=0, padx=5, pady=5, sticky='nsew')
    
    directorio_label = Label(frame_calculo_hashes, text="Directorio:", bg="#e0e0e0")
    directorio_label.grid(row=1, column=0, padx=5, pady=5, sticky='nsew')

    directorio_entry = Entry(frame_calculo_hashes, width=50)
    directorio_entry.grid(row=2, column=0, padx=5, pady=5, sticky='nsew')
    
    # Crear el segundo frame (segunda columna con 1 fila)
    frame2 = Frame(root, bg="#ffffff")  # Opcional: Color de fondo para ver mejor el frame
    frame2.grid(row=0, column=1, padx=10, pady=10, sticky='nsew')
    
    frame2.grid_rowconfigure(0, weight=1)
    frame2.grid_columnconfigure(0, weight=1)
    frame2.grid_columnconfigure(1, weight=0)
    
    resultado_text_widget = Text(frame2, wrap='word', height=40, width=100)
    resultado_text_widget.grid(row=0, column=0, sticky='nsew')
    
    scrollbar = Scrollbar(frame2, command=resultado_text_widget.yview)
    scrollbar.grid(row=0, column=1, sticky='nsew')
    resultado_text_widget.config(yscrollcommand=scrollbar.set)
    
    '''
    # Crear el tercer frame (tercera columna con 3 filas)
    frame3 = Frame(root)  # Opcional: Color de fondo para ver mejor el frame
    frame3.grid(row=0, column=2, rowspan=3, padx=10, pady=10, sticky='nsew')
    
    for i in range(3):
        label = Label(frame3, text=f"Col 3, Fila {i+1}")
        label.grid(row=i, column=0)

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    
    '''
    
    root.mainloop()

#######################################################################################

def listar_usuarios():
    comando = 'powershell.exe -Command "Get-LocalUser | Select-Object Name, FullName, Description, Enabled, PasswordChangeableDate, PasswordExpires, PasswordLastSet, LastLogon, UserMayChangePassword, PrincipalSource"'
    
    resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
    
    salida = resultado.stdout.strip()
    errores = resultado.stderr.strip()
    
    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    # Insertar la salida y los errores en el widget de texto
    if salida:
        resultado_text_widget.insert('1.0', '-------\nSALIDA|\n-------\n\n' + salida + '\n')
        
    if errores:
        resultado_text_widget.insert('1.0', '--------\nERRORES|\n--------\n\n' + errores + '\n')
    
    resultado_text_widget.config(state=DISABLED)

#######################################################################################

import psutil

def particiones():
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
            f"Device: {particion.device}\n"
            f"Mountpoint: {particion.mountpoint}\n"
            f"FileSystemType: {particion.fstype}\n"
            f"TotalSize: {total_size_gb:.2f} GB\n"  # Usamos formato con 2 decimales
            f"Used: {used_gb:.2f} GB\n"             # Usamos formato con 2 decimales
            f"Free: {free_gb:.2f} GB\n"             # Usamos formato con 2 decimales
            f"PercentUsed: {info.percent:.1f}%\n"
            f"{'-' * 40}\n"  # Separador entre particiones
        )
    
    # Unir todos los resultados en un solo texto
    texto_resultados = ''.join(resultados)
        
    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    # Insertar el texto en el widget de texto
    resultado_text_widget.insert('1.0', '-------\nSALIDA|\n-------\n\n----------------------------------------\n' + texto_resultados)
    resultado_text_widget.config(state=DISABLED)
    
#######################################################################################

import os
import hashlib

def listar_archivos(directorio):       
    lista_archivos = []
    for raiz, directorios, archivos in os.walk(directorio):   #Dado un directorio, lo recorre de manera recursiva
        for archivo in archivos:
            ruta_completa = os.path.join(raiz, archivo)    #construimos una ruta completa a un archivo
            lista_archivos.append((archivo, ruta_completa))    #Devolvemos una lista de tuplas de forma (nombreArchivo, ruta)
    return lista_archivos

def calcular_hash_archivo(ruta_archivo):
    hash_md5 = hashlib.md5()           #Especificamos el tipo de hash que vamos a calcular
    try:
        with open(ruta_archivo, 'rb') as f:      #Abre el archivo especificado por ruta_archivo en modo de lectura binaria
            while True:  #Iniciamos un bucle infinito que se utilizará para leer el archivo en bloques.
                chunk = f.read(4096)          #Lee hasta 4096 bytes del archivo en cada iteración del bucle.
                if not chunk:                 #Verificamos si chunk está vacío (es decir, si se ha llegado al final del archivo). Cuando f.read devuelve una cadena vacía, es que se ha leído todo el archivo.
                    break
                hash_md5.update(chunk)
                
    except IOError as e:
        print(f"Error al abrir el archivo {ruta_archivo}: {e}")
        return None
    return hash_md5.hexdigest()

def hashes(directorio_input):
    archivos = listar_archivos(directorio_input)         #Listamos los archivos del directorio especificado en el input
    lista_hashes = []
    for archivo, ruta in archivos:
        hash_valor = calcular_hash_archivo(ruta)         #Calculamos el hash de cada archivo del directorio especificado en el input
        lista_hashes.append((archivo, hash_valor))
    return lista_hashes

# Función para calcular los hashes y mostrar los resultados en el área de texto
def calcular_hashes_gui():
    directorio = directorio_entry.get()
    if not os.path.isdir(directorio):
        resultado_text_widget.config(state=NORMAL)
        resultado_text_widget.delete('1.0', END)
        resultado_text_widget.insert('1.0', 'Error: El directorio no existe o es inválido.\n')
        resultado_text_widget.config(state=DISABLED)
        return
    
    resultados_hashes = hashes(directorio)
    
    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    # Insertar los resultados en el widget de texto
    for archivo, hash_valor in resultados_hashes:
        resultado_text_widget.insert('1.0', f"Archivo: {archivo}\nHash MD5: {hash_valor}\n{'-'*40}\n")
    
    resultado_text_widget.config(state=DISABLED)


#######################################################################################

def información_SO():
    comando = 'systeminfo | findstr /C:"Nombre de host" /C:"Nombre del sistema operativo" /C:"Versión del sistema operativo" /C:"Fabricante del sistema operativo" /C:"Configuración del sistema operativo" /C:"Tipo de compilación del sistema operativo" /C:"Propiedad de" /C:"Fecha de instalación original" /C:"Fabricante del sistema" /C:"Id. del producto" /C:"Modelo el sistema" /C:"Tipo de sistema" /C:"Configuración regional del sistema" /C:"Zona horaria" /C:"Dominio" /C:"Revisión(es)" /C:"Dispositivo de arranque" /C:"Versión del BIOS"'
    
    resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
    
    salida = resultado.stdout.strip()
    errores = resultado.stderr.strip()
    
    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    # Insertar la salida y los errores en el widget de texto
    if salida:
        resultado_text_widget.insert('1.0', '-------\nSALIDA|\n-------\n\n' + salida + '\n')
        
    if errores:
        resultado_text_widget.insert('1.0', '--------\nERRORES|\n--------\n\n' + errores + '\n')
    
    resultado_text_widget.config(state=DISABLED)


#######################################################################################

import winreg

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
            return "vboxmanage.exe no se encontró en el sistema."
        resultado = subprocess.check_output([vboxmanage_path, 'list', 'vms']).decode('utf-8')
        return resultado.strip() if resultado.strip() else "No hay máquinas virtuales en VirtualBox."
    except subprocess.CalledProcessError as e:
        return f"Error al obtener la lista de máquinas virtuales de VirtualBox: {e}"

def obtener_maquinas_virtuales_vmware():
    vmrun_path = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
    cmd = [vmrun_path, "list"]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        vms = result.stdout.strip().split('\n')

        if vms:
            return "\n".join(vms)
        else:
            return "No se encontraron máquinas virtuales."
    
    except subprocess.CalledProcessError as e:
        return f"Error al ejecutar el comando: {e}"


def mostrar_maquinas_virtuales():
    # Obtiene la lista de máquinas virtuales de cada sistema
    salida_vbox = obtener_maquinas_virtuales_virtualbox()
    salida_vmware = obtener_maquinas_virtuales_vmware()

    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)

    # Insertar los resultados en el widget de texto
    resultado_text_widget.insert('1.0', '\nVirtualBox:\n\n' + salida_vbox + '\n' + "-"*80)
    resultado_text_widget.insert('1.0', '\nVMware:\n\n' + salida_vmware + '\n' + "-"*80)
    resultado_text_widget.insert('1.0', '-------\nSALIDA|\n-------\n')

    # Desactivar el estado de solo lectura del widget
    resultado_text_widget.config(state=DISABLED)
    
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
    salida = get_usb_devices()

    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)

    # Verificar si la lista está vacía
    if not salida:
        salida_texto = "No se ha conectado ningún USB aún.\n"
    else:
        # Convertir la lista de diccionarios a una cadena de texto más estética
        salida_texto = '-------\nSALIDA|\n-------\n'
        for dispositivo in salida:
            salida_texto += f"Dispositivo:\n"
            salida_texto += f"  Vendor y Producto: {dispositivo['Vendor_Product']}\n"
            salida_texto += f"  Serial: {dispositivo['Serial']}\n"
            salida_texto += f"  Nombre Amigable: {dispositivo['FriendlyName']}\n"
            salida_texto += "-"*80 + "\n"

    # Insertar los resultados en el widget de texto
    resultado_text_widget.insert('1.0', salida_texto)

    # Desactivar el estado de solo lectura del widget
    resultado_text_widget.config(state=DISABLED)
    
#######################################################################################

def mostrar_perfiles_wifi():
    # Ejecuta el comando y obtiene la salida
    try:
        resultado = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], text=True)
    except subprocess.CalledProcessError as e:
        resultado = f"Error al ejecutar el comando: {e}"
        salida_formateada = f'-------\nSALIDA|\n-------\n{resultado}'
        mostrar_resultado(salida_formateada)
        return

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

    # Obtener detalles de cada perfil
    salida_formateada = ''
    for idx, perfil in enumerate(perfiles, start=1):
        try:
            # Obtener información detallada del perfil
            detalle = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', f'name={perfil}', 'key=clear'], text=True)
        except subprocess.CalledProcessError as e:
            detalle = f"Error al obtener detalles para {perfil}: {e}"
        
        # Añadir el perfil y su detalle a la salida
        salida_formateada += f'\n=== Red WiFi {idx}: {perfil} ===\n'
        salida_formateada += 'Detalles:\n'
        salida_formateada += detalle

    mostrar_resultado(salida_formateada)

def mostrar_resultado(salida):
    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    # Configurar estilos de fuente
    fuente_encabezado = font.Font(resultado_text_widget, size=20, weight='bold')
    fuente_detalles = font.Font(resultado_text_widget, size=10)

    # Insertar el resultado en el widget de texto
    linea = salida.splitlines()
    for texto in linea:
        if texto.startswith('=== Red WiFi'):
            resultado_text_widget.insert(END, texto + '\n', ('encabezado',))
        else:
            resultado_text_widget.insert(END, texto + '\n', ('detalle',))

    # Configurar tags para el formato
    resultado_text_widget.tag_configure('encabezado', font=fuente_encabezado)
    resultado_text_widget.tag_configure('detalle', font=fuente_detalles)
    
    # Desactivar el estado de solo lectura del widget
    resultado_text_widget.config(state=DISABLED)

#######################################################################################

def mostrar_listado_software():
    
    comando = [
        'powershell.exe',
        '-Command',
        "Get-Package | Where-Object { $_.ProviderName -ne 'msu' } | Select-Object Name, Version, ProviderName"
    ]    
    
    resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
    
    salida = resultado.stdout.strip()
    errores = resultado.stderr.strip()
    
    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    # Insertar la salida y los errores en el widget de texto
    if salida:
        resultado_text_widget.insert('1.0', '-------\nSALIDA|\n-------\n\n' + salida + '\n')
        
    if errores:
        resultado_text_widget.insert('1.0', '--------\nERRORES|\n--------\n\n' + errores + '\n')
    
    resultado_text_widget.config(state=DISABLED)

#######################################################################################

import win32com.client

def obtener_informacion_papelera():
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
        
        resultados.append(f"Nombre: {nombre}")
        resultados.append(f"Tipo: {tipo}")
        resultados.append(f"Tamaño: {tamaño} bytes")
        resultados.append(f"Fecha de Eliminación: {fecha_borrado}")
        resultados.append("-" * 40)
    
    return resultados
                
def mostrar_informacion_papelera():
    resultado = obtener_informacion_papelera()
    
    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    if resultado:
        # Insertar la salida en el widget de texto
        resultado_text_widget.insert('1.0', '-----------\nINFORMACIÓN|\n-----------\n\n' + '\n'.join(resultado) + '\n')
    else:
        # Mensaje si no hay archivos en la papelera
        resultado_text_widget.insert('1.0', 'No hay archivos en la papelera.\n')
    
    resultado_text_widget.config(state=DISABLED)

#######################################################################################

import threading

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

def actualizar_texto(texto):
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.insert(END, texto)
    resultado_text_widget.config(state=DISABLED)

def ejecutar_comando(unidad, archivo_salida):
    # Mensaje de "Cargando..." con uso de after para la sincronización
    def mostrar_mensaje_cargando():
        actualizar_texto(f'Cargando el árbol de {unidad}...\n')

    root.after(0, mostrar_mensaje_cargando)

    # Ejecuta el comando para la unidad dada
    comando = [
        'powershell.exe',
        '-Command',
        f"tree /A {unidad}" + "\\" + f" > ./trees/{archivo_salida}"
    ]
    
    resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
    
    # Actualiza el widget de texto con el resultado del comando
    if resultado.returncode == 0:
        resultado_texto = f'Diagrama generado en: /trees/{archivo_salida}\n'
    else:
        resultado_texto = f'Error al generar diagrama para {unidad}\n'
    
    root.after(0, lambda: actualizar_texto(resultado_texto))

def iniciar_comando():
    # Muestra el mensaje de aviso
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    resultado_text_widget.insert(END, "Por favor, espere a que se genere el diagrama de todas las unidades mostradas. Dependiendo del volumen de archivos, algunas pueden tardar más que otras.\n\n")
    resultado_text_widget.insert(END, "NO SELECCIONE OTRO PROCESO HASTA QUE TERMINE ESTE\n\n")
    resultado_text_widget.config(state=DISABLED)
    
    unidades = obtener_unidades_disco()
    for unidad in unidades:
        archivo_salida = f'directory_tree_{limpiar_nombre_archivo(unidad)}.txt'
        threading.Thread(target=ejecutar_comando, args=(unidad, archivo_salida)).start()

###############################################################################################3

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

def mostrar_carpetas_sincronizadas():

    onedrive_path = get_onedrive_path()
    
    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    if onedrive_path:
        # Insertar la salida en el widget de texto
        resultado_text_widget.insert('1.0', f"OneDrive está sincronizado en: {onedrive_path}" + "\n\n")
        synced_folders = get_synced_folders(onedrive_path)
        resultado_text_widget.insert(END, "Carpetas sincronizadas con OneDrive: \n\n")
        for folder in synced_folders:
            resultado_text_widget.insert(END, "- " + folder + "\n")

    else:
        resultado_text_widget.insert(END, "OneDrive no está configurado en este equipo.")

    
# Llamar a la función para crear la ventana principal
create_window()