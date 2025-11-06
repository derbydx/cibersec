# 🔒 OverTheWire - Bandit: Nivel 6 al 7

## 🎯 Objetivo del Nivel 6

La contraseña para el Nivel 7 está almacenada en algún lugar del servidor y tiene las siguientes propiedades exactas:
1.  Es propiedad del usuario: **`bandit7`**
2.  Es propiedad del grupo: **`bandit6`**
3.  Tiene un tamaño exacto de: **`33 bytes`**

### Solución

1.  **Conexión SSH:** Nos conectamos usando las credenciales del nivel anterior.
    * **Usuario:** `bandit6`
    * **Contraseña:** **[La contraseña real del Nivel 6]**

2.  **Estrategia de Búsqueda:** Dado que el archivo puede estar **en cualquier lugar** del servidor, el comando más adecuado para aplicar múltiples filtros de metadatos (usuario, grupo y tamaño) es **`find`**, buscando desde el directorio raíz (`/`).

3.  **Ejecución del Comando `find`:** Se utiliza el comando `find` con los siguientes parámetros:
    * `-type f`: Busca solo archivos (no directorios).
    * `-user bandit7`: Busca archivos cuyo propietario sea `bandit7`.
    * `-group bandit6`: Busca archivos cuyo grupo sea `bandit6`.
    * `-size 33c`: Busca archivos con un tamaño exacto de 33 caracteres/bytes.
    * `2>/dev/null`: Se redirigen los errores de "Permiso denegado" (propios de buscar en directorios restringidos como `/proc` o `/root`) al "agujero negro" de la terminal para mantener la salida limpia.

    * **Comando de Búsqueda:** `find / -type f -user bandit7 -group bandit6 -size 33c 2>/dev/null`

4.  **Resultado de la Búsqueda:** El comando revela la ruta absoluta del archivo:
    * **Ruta:** `/var/lib/dpkg/info/bandit7.password`

5.  **Leer la Contraseña:** Una vez identificada la ruta, usamos `cat` para leer su contenido.
    * **Comando:** `cat /var/lib/dpkg/info/bandit7.password`
    * **Resultado (Password Nivel 7):** **morbNTDkSW6jIlUc0ymOdMaLnOlFVAaj**

---

## 🔑 Prueba de Éxito

<img width="830" height="99" alt="image" src="https://github.com/user-attachments/assets/7a69467d-e7f8-465b-9996-29a832e31947" />

---

[➡️ Siguiente Nivel: Nivel 7 al 8](Nivel_07_a_08.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
