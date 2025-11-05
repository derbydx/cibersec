# 🔒 OverTheWire - Bandit: Nivel 1 al 2

## 🎯 Objetivo del Nivel 1

La contraseña para el Nivel 2 está almacenada en el directorio home del usuario `bandit1` en un archivo llamado **`-`** (un guion).

### Solución

1.  **Conexión SSH:** Nos conectamos al servidor usando la contraseña obtenida del Nivel 0.
    * **Usuario:** `bandit1`
    * **Contraseña:** **[La contraseña real del Nivel 1]**
<img width="477" height="152" alt="image" src="https://github.com/user-attachments/assets/3999b563-e993-46b7-9920-c694a3566718" />

2.  **El Desafío del Guion (`-`):** Si intentamos leer el archivo usando el comando `cat -`, el programa `cat` interpretará el guion como una señal para leer desde la entrada estándar (teclado), no como un nombre de archivo.

3.  **La Solución (Ruta Relativa):** Para forzar a `cat` a tratar el guion como un nombre de archivo en el directorio actual, debemos anteponer la ruta relativa al directorio actual (`./`).
    * **Comando para obtener la contraseña:** `cat ./-`
<img width="328" height="71" alt="image" src="https://github.com/user-attachments/assets/ac7f015c-dae8-4db3-9025-4b1cf0b88f43" />

    * **Resultado (Password Nivel 2):** **[263JGJPfgU6LtdEvgfWU1XP5yac29mFx]**

---

## 🔑 Prueba de Éxito




---

[➡️ Siguiente Nivel: Nivel 2 al 3](Nivel_02_a_03.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
