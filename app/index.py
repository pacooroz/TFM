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
    global resultado_text_widget  # Definir el widget de texto globalmente para actualizarlo en listar_usuarios()

    root = Tk()

    # Crear el primer frame (primera columna con 3 filas)
    frame1 = Frame(root)  # Opcional: Color de fondo para ver mejor el frame
    frame1.grid(row=0, column=0, rowspan=3, padx=10, pady=10, sticky='nsew')
    
    boton1 = Button(root, text="Listar usuarios", bg="gray", command=listar_usuarios)
    boton1.grid(row=0, column=0)
        
    # Crear el segundo frame (segunda columna con 1 fila)
    frame2 = Frame(root)  # Opcional: Color de fondo para ver mejor el frame
    frame2.grid(row=0, column=1, padx=10, pady=10, sticky='nsew')
    
    resultado_text_widget = Text(frame2, wrap='word')
    resultado_text_widget.grid(row=0, column=0, sticky='nsew')
    
    scrollbar = Scrollbar(frame2, command=resultado_text_widget.yview)
    scrollbar.grid(row=0, column=1, sticky='ns')
    resultado_text_widget.config(yscrollcommand=scrollbar.set)
    
    # Crear el tercer frame (tercera columna con 3 filas)
    frame3 = Frame(root)  # Opcional: Color de fondo para ver mejor el frame
    frame3.grid(row=0, column=2, rowspan=3, padx=10, pady=10, sticky='nsew')
    
    for i in range(3):
        label = Label(frame3, text=f"Col 3, Fila {i+1}")
        label.grid(row=i, column=0)

    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(1, weight=1)
    
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

# Llamar a la función para crear la ventana principal
create_window()