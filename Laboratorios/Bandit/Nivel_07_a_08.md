# 🔒 OverTheWire - Bandit: Nivel 7 al 8

## 🎯 Objetivo del Nivel 7

La contraseña para el Nivel 8 está almacenada en el archivo **`data.txt`** y se encuentra inmediatamente al lado de la palabra **`millionth`**.

### Solución

1.  **Conexión SSH:** Nos conectamos usando las credenciales del nivel anterior.
    * **Usuario:** `bandit7`
    * **Contraseña:** **[La contraseña real del Nivel 7]**

2.  **Estrategia de Búsqueda:** Utilizamos el comando **`grep`** para buscar de forma eficiente la palabra clave dentro del contenido del archivo.

3.  **Ejecución del Comando `grep`:**
    * **Comando:** `grep millionth data.txt`

    * **Resultado de la Búsqueda:**
        ```
        millionth       dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc
        ```
    * **Password Nivel 8:** **dfwvzFQi4mU0wfNbFOe9RoWskMLg7eEc**

---

## 🔑 Prueba de Éxito

<img width="500" height="88" alt="image" src="https://github.com/user-attachments/assets/1c42fffb-bf1b-4f10-8a66-26758d6f56d0" />

---

[➡️ Siguiente Nivel: Nivel 8 al 9](Nivel_08_a_09.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
