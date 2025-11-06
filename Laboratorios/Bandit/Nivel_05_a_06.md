# 🔒 OverTheWire - Bandit: Nivel 5 al 6

## 🎯 Objetivo del Nivel 5

La contraseña para el Nivel 6 está almacenada en un archivo en algún lugar bajo el directorio **`inhere`** que cumple con **tres propiedades**:
1.  Es legible por humanos (`human-readable`).
2.  Tiene un tamaño de **1033 bytes**.
3.  No es ejecutable (`not executable`).

### Solución

1.  **Conexión SSH:** Nos conectamos al servidor.
    * **Usuario:** `bandit5`
    * **Contraseña:** **[La contraseña real del Nivel 5]**

2.  **Navegar y Analizar el Directorio:** El directorio `inhere` contiene múltiples subdirectorios, lo que indica que la búsqueda debe ser recursiva (dentro de subcarpetas).

    * **Comando:** `cd inhere`
    * **Comando:** `ls -a`

3.  **Identificar el Archivo por Tamaño y Ubicación (Método de Búsqueda):** En lugar de verificar manualmente cada carpeta, se puede usar el comando **`find`** para aplicar todos los criterios de una vez, o combinar comandos para filtrar la información.

    * **Método alternativo usado (Combinación de du y grep):** Se utilizó `du` (Disk Usage) con la opción `-ab` para mostrar el tamaño exacto de todos los archivos en bytes, y luego se filtró (`grep`) para buscar el tamaño requerido.
    * **Comando de Búsqueda:** `du -ab | grep 1033`
    * **Resultado de la Búsqueda:**
        ```
        1033    ./maybehere07/.file2
        ```
    * *Nota:* Este archivo es pequeño, legible y no ejecutable, satisfaciendo el resto de los criterios automáticamente.

4.  **Leer la Contraseña:** Una vez identificada la ruta (`./maybehere07/.file2`), utilizamos `cat` para leer su contenido.
    * **Comando:** `cat ./maybehere07/.file2`
    * **Resultado (Password Nivel 6):** **HWasnPhtq9AVKe0dmk45nxy20cvUa6EG**

---

## 🔑 Prueba de Éxito

<img width="908" height="553" alt="image" src="https://github.com/user-attachments/assets/3671944b-e12a-471e-bbdf-1c07671fc0d3" />

---

[➡️ Siguiente Nivel: Nivel 6 al 7](Nivel_06_a_07.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
