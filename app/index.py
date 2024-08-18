import queue
import sys
from tkinter import *
import subprocess
from tkinter import font
from PIL import ImageTk, Image
import informe_completo
import os

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

def resource_path(relative_path):
    """ Devuelve el path absoluto al recurso en la carpeta temporal si se está ejecutando como un .exe """
    try:
        # PyInstaller crea una carpeta temporal para los recursos
        base_path = sys._MEIPASS
    except Exception:
        # Si no se está ejecutando desde un .exe, usa el directorio actual
        base_path = os.path.dirname(".")
        
    return os.path.join(base_path, relative_path)

icono_path = resource_path("icono.png")

icono = PhotoImage(file=icono_path)
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

    icono_path = resource_path("logo.png")
    logo = PhotoImage(file=icono_path)
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
    
    botonInforme = Button(root, text="Generar Informe Completo", bg="red", fg="white", command=generar_infome)
    botonInforme.grid(row=1, column=1, padx=5, pady=5, sticky='nsew')
    
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
import concurrent.futures

# Función que calcula el hash de un archivo
def calcular_hash_archivo(ruta_archivo, algoritmo='md5'):
    hash_obj = hashlib.new(algoritmo)
    try:
        with open(ruta_archivo, 'rb') as archivo:
            while True:
                bloque = archivo.read(4096)
                if not bloque:
                    break
                hash_obj.update(bloque)
        return hash_obj.hexdigest()
    except (OSError, IOError) as e:
        print(f'No se puede leer el archivo {ruta_archivo}: {e}')
        return None

# Función que procesa un archivo
def procesar_archivo(ruta_archivo):
    hash_valor = calcular_hash_archivo(ruta_archivo)
    if hash_valor:
        return ruta_archivo, hash_valor
    return None

# Función que escanea un directorio y calcula los hashes de los archivos
def escanear_directorio(directorio):
    archivos = []
    resultados = []

    # Verificar si la entrada es un archivo
    if os.path.isfile(directorio):
        archivos.append(directorio)
    else:
        # Si es un directorio, recorrer el directorio
        for carpeta_raiz, _, archivos_nombres in os.walk(directorio):
            for archivo_nombre in archivos_nombres:
                archivos.append(os.path.join(carpeta_raiz, archivo_nombre))

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        for resultado in executor.map(procesar_archivo, archivos):
            if resultado is not None:
                resultados.append(resultado)

    return resultados

# Función para calcular los hashes y mostrar los resultados en el área de texto
def calcular_hashes_gui():
    # Mostrar "Cargando..." en el widget de texto y actualizar la GUI
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    resultado_text_widget.insert('1.0', 'Cargando...\n')
    resultado_text_widget.config(state=DISABLED)
    resultado_text_widget.update_idletasks()

    # Obtener el directorio o archivo de entrada
    ruta = directorio_entry.get()

    if not os.path.exists(ruta):
        resultado_text_widget.config(state=NORMAL)
        resultado_text_widget.delete('1.0', END)
        resultado_text_widget.insert('1.0', 'Error: La ruta no existe o es inválida.\n')
        resultado_text_widget.config(state=DISABLED)
        return

    # Función para calcular los hashes y actualizar la GUI con los resultados
    def calcular_y_mostrar_resultados():
        resultados_hashes = escanear_directorio(ruta)

        resultado_text_widget.config(state=NORMAL)
        resultado_text_widget.delete('1.0', END)

        for archivo, hash_valor in resultados_hashes:
            resultado_text_widget.insert('1.0', f"Archivo: {archivo}\nHash MD5: {hash_valor}\n{'-'*40}\n")

        resultado_text_widget.config(state=DISABLED)

    # Ejecutar la función en un hilo separado para no bloquear la GUI
    threading.Thread(target=calcular_y_mostrar_resultados).start()


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
            print(f"VirtualBox no está instalado o el archivo vboxmanage.exe no ha sido encontrado en {ruta_instalacion}")
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
    print(salida_vmware)
    salida_vmware_str = '\n'.join(salida_vmware)

    # Limpiar el contenido actual del widget de texto
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)

    # Insertar los resultados en el widget de texto
    resultado_text_widget.insert('1.0', '\nVirtualBox:\n\n' + salida_vbox + '\n' + "-"*80)
    
    if salida_vmware == []:
        resultado_text_widget.insert('1.0', '\nVMware:\n\n' + "No se ha encontrado máquinas VMWare." + '\n' + "-"*80)
    else:
        resultado_text_widget.insert('1.0', '\nVMware:\n\n' + salida_vmware_str + '\n' + "-"*80)
        
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
    # Verifica si el servicio wlansvc está en ejecución
    try:
        servicio_estado = subprocess.check_output(['sc', 'query', 'wlansvc'], text=True)
        if "RUNNING" not in servicio_estado:
            mostrar_resultado("El servicio 'wlansvc' no está en ejecución.")
            return None
        else:
            try:
                resultado = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles'], text=True)
                if "Perfil de todos los usuarios" not in resultado or "No hay ninguna interfaz inalámbrica en el sistema." in resultado:
                    resultado = "No se ha conectado a ninguna red WiFi aún."
                    mostrar_resultado(resultado)
                    return
            except subprocess.CalledProcessError as e:
                resultado = f"Error al ejecutar el comando: {e}"
                salida_formateada = f'-------\nSALIDA|\n-------\n{resultado}'
                mostrar_resultado(salida_formateada)
                return

    except subprocess.CalledProcessError as e:
        mostrar_resultado(f"Error al verificar el estado del servicio 'wlansvc': {e}")
        return None

    # Ejecuta el comando y obtiene la salida

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
    resultado_text_widget.insert(END, 'Es necesario que el servicio Wlansvc esté en ejecución.\n\n')
    
    # Configurar estilos de fuente
    fuente_encabezado = font.Font(resultado_text_widget, size=20, weight='bold')
    fuente_detalles = font.Font(resultado_text_widget, size=10)

    # Insertar el resultado en el widget de texto
    linea = salida.splitlines()
    for texto in linea:
        if texto.startswith('=== Red WiFi'):
            resultado_text_widget.insert(END, texto + '\n', ('encabezado',))
        elif texto.startswith("El servicio 'wlansvc' no está en ejecución."):
            resultado_text_widget.insert(END, texto + '\n')
        elif texto.startswith("No se ha conectado a ninguna red WiFi aún."):
            resultado_text_widget.insert(END, texto + '\n')
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
import win32timezone

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
    unidades = []
    try:
        result = subprocess.run(['wmic', 'logicaldisk', 'get', 'name'], capture_output=True, text=True)
        result.check_returncode()
        lineas = result.stdout.splitlines()
        if len(lineas) > 1:
            unidades = [line.strip() for line in lineas[1:] if line.strip()]
    except subprocess.CalledProcessError as e:
        print(f'Error al obtener unidades de disco: {e}')
    except Exception as e:
        print(f'Error inesperado: {e}')
    return unidades

def limpiar_nombre_archivo(nombre):
    return nombre.replace(":", "").replace("\\", "_").replace("/", "_").replace(" ", "_")

def crear_directorio_si_no_existe(directorio):
    if not os.path.exists(directorio):
        os.makedirs(directorio)

def actualizar_textoTree(texto):
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.insert(END, texto)
    resultado_text_widget.config(state=DISABLED)

def ejecutar_comando(unidad, archivo_salida):
    def mostrar_mensaje_cargando():
        actualizar_textoTree(f'Cargando el árbol de {unidad}...\n')
    
    root.after(0, mostrar_mensaje_cargando)
    
    if getattr(sys, 'frozen', False):  # Si es un .exe compilado
        directorio_base = os.path.dirname(sys.executable)
    else:
        directorio_base = os.path.dirname(os.path.abspath(__file__))
    
    archivo_salida_path = os.path.join(directorio_base, archivo_salida)

    print(f"Directorio base: {directorio_base}")
    print(f"Archivo de salida: {archivo_salida_path}")

    comando = (
        f'powershell.exe -Command "tree /A {unidad}\\ | Out-File -FilePath \'{archivo_salida_path}\' -Encoding UTF8"'
    )

    print(f"Comando a ejecutar: {comando}")
    ruta_relativa = os.path.relpath(archivo_salida_path, start=directorio_base)

    try:
        resultado = subprocess.run(comando, shell=True, capture_output=True, text=True)
        print(f"Resultado stdout: {resultado.stdout}")
        print(f"Resultado stderr: {resultado.stderr}")
        resultado.check_returncode()
        if resultado.returncode == 0:
            print(f"Archivo generado correctamente: {archivo_salida_path}")
            resultado_texto = f'Diagrama generado en: /{ruta_relativa}\n'

        else:
            print(f"Error al generar archivo para {unidad}")
            resultado_texto = f'Error al generar diagrama para {unidad}\n'

    except subprocess.CalledProcessError as e:
        print(f"Error al ejecutar comando: {e}")
        resultado_texto = f'Error al ejecutar comando para {unidad}: {e}\n'

    except Exception as e:
        print(f"Error inesperado: {e}")
        resultado_texto = f'Error inesperado al ejecutar comando para {unidad}: {e}\n'

    root.after(0, lambda: actualizar_textoTree(resultado_texto))

def iniciar_comando():
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

################################################################################################3

'''
def generar_infome():
    
    # Generar los archivos HTML
    informe_completo.listar_usuarios_html()
    informe_completo.particiones_html()
    informe_completo.información_SO()
    informe_completo.mostrar_maquinas_virtuales()
    informe_completo.generar_indice_html()
    informe_completo.mostrar_usbs()
    informe_completo.mostrar_perfiles_wifi()
    informe_completo.listado_software()
    informe_completo.mostrar_informacion_papelera()
    informe_completo.iniciar_comando()
'''
def actualizar_texto(linea, mensaje):
    
    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete(f"{linea}.0", f"{linea}.end")
    resultado_text_widget.insert(f"{linea}.0", mensaje)
    resultado_text_widget.config(state=DISABLED)
    resultado_text_widget.yview(END)  # Desplazar hacia abajo para mostrar el texto más reciente

def mostrar_mensaje_y_ejecutar(linea, mensaje, funcion):
    def wrapper():
        # Ejecutar la función
        funcion()
        # Mostrar mensaje de finalización
        root.after(0, lambda: actualizar_texto(linea, mensaje + " --> ¡Hecho!"))
        # Ejecutar la siguiente tarea en la cola
        if not tarea_queue.empty():
            next_linea, next_mensaje, next_funcion = tarea_queue.get()
            mostrar_mensaje_y_ejecutar(next_linea, next_mensaje, next_funcion)
    
    # Ejecutar en un hilo separado para mantener la interfaz de usuario responsiva
    threading.Thread(target=wrapper).start()

def generar_infome():
    global tarea_queue
    tarea_queue = queue.Queue()

    resultado_text_widget.config(state=NORMAL)
    resultado_text_widget.delete('1.0', END)
    
    # Añadir las tareas a la cola
    informe_completo.generar_indice_html()

    tarea_queue.put(("1", "Generando Lista de Usuarios...", informe_completo.listar_usuarios_html))
    tarea_queue.put(("2", "Generando Particiones...", informe_completo.particiones_html))
    tarea_queue.put(("3", "Generando Información del SO...", informe_completo.información_SO))
    tarea_queue.put(("4", "Mostrando Máquinas Virtuales...", informe_completo.mostrar_maquinas_virtuales))
    tarea_queue.put(("5", "Mostrando Dispositivos USB...", informe_completo.mostrar_usbs))
    tarea_queue.put(("6", "Mostrando Perfiles Wi-Fi...", informe_completo.mostrar_perfiles_wifi))
    tarea_queue.put(("7", "Listado de Software...", informe_completo.listado_software))
    tarea_queue.put(("8", "Mostrando Información de la Papelera...", informe_completo.mostrar_informacion_papelera))
    tarea_queue.put(("9", "Mostrando Carpetas Sincronizadas con OneDrive...", informe_completo.mostrar_carpetas_sin))
    tarea_queue.put(("10", "Calculando Hashes...", informe_completo.generar_doc_hashes))

    # Obtener unidades de disco
    unidades_disco = obtener_unidades_disco()
    
    # Añadir las tareas de árbol de directorios para cada unidad de disco
    for i, unidad in enumerate(unidades_disco, start=11):
        mensaje = f"Generando árbol de directorios de la unidad {unidad} en /trees/AutoReport/..."
        tarea_queue.put((str(i), mensaje, lambda u=unidad: informe_completo.iniciar_comando(u)))
    
    # Insertar líneas en el widget de texto para cada tarea
    resultado_text_widget.config(state=NORMAL)
    for i in range(1, tarea_queue.qsize() + 1):
        resultado_text_widget.insert(END, f"{i}.0 {tarea_queue.queue[i-1][1]}\n")
    resultado_text_widget.config(state=DISABLED)
    
    # Ejecutar la primera tarea en la cola
    if not tarea_queue.empty():
        next_linea, next_mensaje, next_funcion = tarea_queue.get()
        mostrar_mensaje_y_ejecutar(next_linea, next_mensaje, next_funcion)

# Llamar a la función para crear la ventana principal
create_window()