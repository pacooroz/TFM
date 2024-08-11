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
    hash_obj = hashlib.new(algoritmo)

    # Lee el archivo en bloques para no cargarlo todo en memoria a la vez
    with open(ruta_archivo, 'rb') as archivo:
        while chunk := archivo.read(8192):
            hash_obj.update(chunk)

    # Devuelve el hash en formato hexadecimal
    return hash_obj.hexdigest()

extensiones_temporales = ['.tmp', '.bak', '.swp', '.swo', '.dll', '.sys']

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
                    except PermissionError:
                        print(f"Permiso denegado para leer el archivo: {ruta_archivo}")
                    except Exception as e:
                        print(f"Error al calcular el hash para {ruta_archivo}: {e}")

'''
def calcular_hash_archivo(ruta_archivo, algoritmo='md5'):
    """
    Calcula el hash de un archivo usando el algoritmo especificado.
    :param ruta_archivo: Ruta al archivo
    :param algoritmo: Algoritmo de hash (por defecto 'md5')
    :return: El hash del archivo en formato hexadecimal
    """
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

def procesar_archivo(ruta_archivo):
    hash_valor = calcular_hash_archivo(ruta_archivo)
    if hash_valor:
        print(f'{ruta_archivo}, {hash_valor}')

def escanear_directorio(directorio):
    """
    Escanea todos los archivos en un directorio y calcula su hash.
    :param directorio: Ruta al directorio
    """
    archivos = []
    for carpeta_raiz, _, archivos_nombres in os.walk(directorio):
        for archivo_nombre in archivos_nombres:
            archivos.append(os.path.join(carpeta_raiz, archivo_nombre))
    
    # Usar ThreadPoolExecutor para calcular hashes en paralelo
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        executor.map(procesar_archivo, archivos)

# Ejemplo de uso
directorio = '/'  # Cambia esto a la ruta de inicio en tu sistema

# Registra el tiempo antes de ejecutar la función
inicio = time.time()

escanear_directorio(directorio)

# Registra el tiempo después de ejecutar la función
fin = time.time()

# Calcula y muestra el tiempo total de ejecución
tiempo_total = fin - inicio
print(f'Tiempo total de ejecución: {tiempo_total:.2f} segundos')
'''