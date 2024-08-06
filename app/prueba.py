import os
import hashlib
import concurrent.futures
import time  # Importa el módulo time para medir el tiempo

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
