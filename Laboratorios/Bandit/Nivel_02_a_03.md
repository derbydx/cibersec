# 🔒 OverTheWire - Bandit: Nivel 2 al 3

## 🎯 Objetivo del Nivel 2

La contraseña para el Nivel 3 se encuentra en un archivo en el directorio home del usuario `bandit2`. El nombre del archivo contiene espacios: **`--spaces in this filename--`**.

### Solución

1.  **Conexión SSH:** Nos conectamos al servidor usando la contraseña obtenida del nivel anterior.
    * **Usuario:** `bandit2`
    * **Contraseña:** **[263JGJPfgU6LtdEvgfWU1XP5yac29mFx]**

2.  **El Desafío de los Espacios:** Cuando la terminal encuentra espacios, los interpreta como **separadores** entre diferentes comandos, argumentos o nombres de archivo. Si intentáramos `cat --spaces in this filename--`, la terminal intentaría ejecutar `cat` con cuatro argumentos separados.

3.  **La Solución (Escapado de Espacios o Comillas):** Para que la terminal trate el nombre completo como una única cadena (un solo argumento), hay dos métodos comunes:

    * **Método 1: Usar Comillas Dobles (`"`)** (más limpio)
        * **Comando:** `cat "--spaces in this filename--"`

    * **Método 2: Usar Barra Invertida (`\`)** (escapar cada espacio)
        * **Comando:** `cat --spaces\ in\ this\ filename--`

* **Método 3: Usar punto Slash (`./`)** (para llamar desde home)
        * **Comando:** `cat "./--spaces in this filename--`
  
    * **Resultado (Password Nivel 3):** **[MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx]**

---

## 🔑 Prueba de Éxito

<img width="451" height="72" alt="image" src="https://github.com/user-attachments/assets/9ebadf13-a989-4a7c-87f9-20f0cb7a1256" />

---

[➡️ Siguiente Nivel: Nivel 3 al 4](Nivel_03_a_04.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
