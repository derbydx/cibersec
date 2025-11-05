# 🔒 OverTheWire - Bandit: Nivel 0 al 1

## 🎯 Objetivo del Nivel 0

El objetivo es conectarse al servidor SSH y encontrar la contraseña para el Nivel 1.

### Solución

1.  **Conexión:** Se utiliza el protocolo SSH con el usuario `bandit0` en el puerto `2220`.
    * **Comando:** `ssh bandit0@bandit.labs.overthewire.org -p 2220`
    * **Contraseña:** `bandit0` (es la misma que el usuario en este primer nivel).
2.  **Encontrar la Contraseña:** Una vez dentro del servidor, la contraseña para el siguiente nivel se encuentra en el archivo `readme`.
    * **Comando:** `cat readme`
    * **Resultado (Password Nivel 1):** [ZjLjTmM6FvvyRnrb2rfNWOZOTa6ip5If]

---

[➡️ Siguiente Nivel: Nivel 1 al 2](Nivel_01_a_02.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
