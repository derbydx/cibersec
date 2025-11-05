# 🔒 OverTheWire - Bandit: Nivel 0 al 1

## 🎯 Objetivo del Nivel 0

El objetivo es conectarse al servidor SSH y encontrar la contraseña para el Nivel 1.

### Solución

1.  **Conexión:** Se utiliza el protocolo SSH con el usuario `bandit0` en el puerto `2220`.
    * **Comando:** `ssh bandit0@bandit.labs.overthewire.org -p 2220`
    * <img width="607" height="503" alt="image" src="https://github.com/user-attachments/assets/eb4df696-e4a4-4857-a31a-8910e1ecc228" />

    * **Contraseña:** `bandit0` (es la misma que el usuario en este primer nivel).
2.  **Encontrar la Contraseña:** Una vez dentro del servidor, la contraseña para el siguiente nivel se encuentra en el archivo `readme`.
    * **Comando:** `ls` para ver los archivos disponibles   
    * **Comando:** `cat readme` para leer el archivo readme
    * **Resultado (Password Nivel 1):** [ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If]

---![Uploading image.png…]()


[➡️ Siguiente Nivel: Nivel 1 al 2](Nivel_01_a_02.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
