from tkinter import *
import subprocess

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

#######################################################################################
def create_window():
    global resultado_text_widget, directorio_entry # Definir el widget de texto globalmente para actualizarlo en listar_usuarios()

    root = Tk()
    root.title("Informe Forense")
    root.configure(bg="#f0f0f0")  # Fondo de la ventana

    # Crear el primer frame (primera columna con 3 filas)
    frame1 = Frame(root, bg="#f0f0f0")
    frame1.grid(row=0, column=0, rowspan=4, padx=10, pady=10, sticky='ns')
    
    boton1 = Button(frame1, text="Listar usuarios", bg="#007bff", fg="#ffffff", command=listar_usuarios)
    boton1.grid(row=0, column=0, padx=5, pady=5, sticky='ew')
    
    boton2 = Button(frame1, text="Particiones", bg="#007bff", fg="#ffffff", command=particiones)
    boton2.grid(row=1, column=0, padx=5, pady=5, sticky='ew')
    
    boton3 = Button(frame1, text="Cálculo de Hashes", bg="#007bff", fg="#ffffff", command=calcular_hashes_gui)
    boton3.grid(row=2, column=0, padx=5, pady=5, sticky='ew')
    
    boton4 = Button(frame1, text="Detalles S.O", bg="#007bff", fg="#ffffff", command=información_SO)
    boton4.grid(row=3, column=0, padx=5, pady=5, sticky='ew')
    
    boton5 = Button(frame1, text="Obtener Máquinas Virtuales", bg="#007bff", fg="#ffffff", command=mostrar_maquinas_virtuales)
    boton5.grid(row=4, column=0, padx=5, pady=5, sticky='ew')
    
    # Crear el frame con fondo de color alrededor del botón y el input
    frame_calculo_hashes = Frame(frame1, bg="#ffcccc", borderwidth=2, relief="groove")
    frame_calculo_hashes.grid(row=2, column=0, padx=5, pady=5, sticky='ew')

    boton3 = Button(frame_calculo_hashes, text="Calcular Hashes", bg="#007bff", fg="#ffffff", command=calcular_hashes_gui)
    boton3.grid(row=0, column=0, padx=5, pady=5, sticky='ew')

    directorio_label = Label(frame_calculo_hashes, text="Directorio:", bg="#e0e0e0")
    directorio_label.grid(row=1, column=0, padx=5, pady=5, sticky='w')

    directorio_entry = Entry(frame_calculo_hashes, width=50)
    directorio_entry.grid(row=2, column=0, padx=5, pady=5, sticky='ew')
    
    # Crear el segundo frame (segunda columna con 1 fila)
    frame2 = Frame(root, bg="#ffffff")  # Opcional: Color de fondo para ver mejor el frame
    frame2.grid(row=1, column=1, padx=10, pady=10, sticky='nsew')
    
    resultado_text_widget = Text(frame2, wrap='word', height=30, width=100)
    resultado_text_widget.grid(row=0, column=0, sticky='nsew')
    
    scrollbar = Scrollbar(frame2, command=resultado_text_widget.yview)
    scrollbar.grid(row=0, column=1, sticky='ns')
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
    
# Llamar a la función para crear la ventana principal
create_window()