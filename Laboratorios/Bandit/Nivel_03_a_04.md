# 🔒 OverTheWire - Bandit: Nivel 3 al 4

## 🎯 Objetivo del Nivel 3

La contraseña para el Nivel 4 está almacenada en un **archivo oculto** dentro de un subdirectorio llamado **`inhere`** en el directorio principal (`home`) del usuario.

### Solución

1.  **Conexión SSH:** Nos conectamos al servidor usando la contraseña obtenida del nivel anterior.
    * **Usuario:** `bandit3`
    * **Contraseña:** **[MNk8KNH3Usiio41PRUEoDFPqfxLPlSmx]**

2.  **Navegar al Directorio:** Primero debemos entrar al directorio especificado.
    * **Comando:** `cd inhere`

3.  **Encontrar el Archivo Oculto:** En sistemas basados en Unix/Linux, un archivo es "oculto" si su nombre comienza con un **punto (`.`)**. El comando `ls` por sí solo no los muestra.
    * **Comando para listar archivos (incluyendo ocultos):** `ls -la` o `ls -a`
    * Al ejecutar el comando, se revelará un archivo que comienza con un punto. En nuestro caso, el archivo es ...Hiding-From-You 

4.  **Leer la Contraseña:** Una vez identificado el nombre del archivo oculto, utilizamos `cat` para leer su contenido.
    * **Comando:** `cat ./...Hiding-From-You`
    * **Resultado (Password Nivel 4):** **[2WmrDFRmJIq3IPxneAaMGhap0pFhF3NJ]**

---

## 🔑 Prueba de Éxito

<img width="484" height="173" alt="image" src="https://github.com/user-attachments/assets/62dab6fe-f176-49f8-aa7b-1b9930297c18" />


---

[➡️ Siguiente Nivel: Nivel 4 al 5](Nivel_04_a_05.md) 
[⬅️ Volver al Índice de Labs](../../README.md)
