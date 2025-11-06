# 🔒 OverTheWire - Bandit: Nivel 4 al 5

## 🎯 Objetivo del Nivel 4

La contraseña para el Nivel 5 está almacenada en el **único archivo legible por humanos** dentro del subdirectorio **`inhere`**.

### Solución

1.  **Conexión SSH:** Iniciamos sesión con las credenciales del nivel anterior.
    * **Usuario:** `bandit4`
    * **Contraseña:** **[2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ]**

2.  **Navegar y Listar:** Entramos al directorio y listamos su contenido.
    * **Comandos:**
        ```bash
        cd inhere
        ls
        ```
    * El listado mostrará varios archivos, pero no es obvio cuál contiene la contraseña, ya que es un archivo tipo ASCII.

3.  **Identificar Archivos Legibles:** Para saber qué tipo de contenido tiene un archivo (texto, binario, imagen, etc.), utilizamos el comando **`file`**.
    * **Comando:** `file ./*`
    * El `file ./*` revisará todos los archivos en el directorio actual.
    * La salida mostrará que todos son archivos binarios o datos, **excepto uno** que dirá algo como "ASCII text" o "text/plain; charset=us-ascii" (este es el archivo legible por humanos).

4.  **Leer la Contraseña:** Usamos `cat` en el archivo identificado como legible por humanos.
    * **Comando:** `cat ./-file07`
    * **Resultado (Password Nivel 5):** **[2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ]**

---

## 🔑 Prueba de Éxito

<img width="834" height="401" alt="image" src="https://github.com/user-attachments/assets/c5b5dcc8-1d25-4469-9bf8-450dfd44d627" />

---

[➡️ Siguiente Nivel: Nivel 5 al 6](Nivel_05_a_06.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
