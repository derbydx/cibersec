# 🔒 OverTheWire - Bandit: Nivel 8 al 9

## 🎯 Objetivo del Nivel 8

La contraseña para el Nivel 9 está almacenada en el archivo **`data.txt`** y es la **única línea de texto que aparece solo una vez** (la línea única/uncommon).

### Solución

1.  **Conexión SSH:** Nos conectamos usando las credenciales del nivel anterior.
    * **Usuario:** `bandit8`
    * **Contraseña:** **[La contraseña real del Nivel 8]**

2.  **Estrategia de Filtrado:** Para encontrar la línea que ocurre solo una vez en un archivo con muchas repeticiones, debemos:
    a.  **Ordenar (`sort`):** Agrupa todas las líneas idénticas consecutivamente, lo cual es un requisito para que `uniq` funcione correctamente.
    b.  **Filtrar (`uniq -u`):** Procesa el resultado ordenado. La opción `-u` (unique) hace que `uniq` solo muestre las líneas que **no se repiten**.

3.  **Ejecución de la Cadena de Comandos (Piping):**
    * **Comando:** `sort data.txt | uniq -u`

    * **Resultado de la Búsqueda:** El comando devuelve la línea única, que es la contraseña.
        ```
        4CKMh1JI91bUIZZPXDqGanal4xvAg0JM
        ```
    * **Password Nivel 9:** **4CKMh1JI91bUIZZPXDqGanal4xvAg0JM**

---

## 🔑 Prueba de Éxito

<img width="400" height="90" alt="image" src="https://github.com/user-attachments/assets/a9f1f5cb-55ec-4614-8001-61653ac0838c" />

---

[➡️ Siguiente Nivel: Nivel 9 al 10](Nivel_09_a_10.md)
[⬅️ Volver al Índice de Labs](../../README.md)
