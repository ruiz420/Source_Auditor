# Despliegue gratis en Render

Esta app necesita backend Flask/Python, por eso no funciona en GitHub Pages.
La opcion mas simple gratis es GitHub + Render.

## 1. Subir a GitHub

1. Entra a https://github.com
2. Crea un repositorio nuevo.
3. Sube estos archivos del proyecto:
   - app.py
   - requirements.txt
   - Dockerfile
   - render.yaml
   - templates/
   - static/

No subas la carpeta `url-checker-web`, `__pycache__`, CSV, XLSX ni capturas generadas.

## 2. Crear Web Service en Render

1. Entra a https://render.com
2. Crea cuenta o inicia sesion.
3. Click en New +.
4. Selecciona Web Service.
5. Conecta tu repositorio de GitHub.
6. Render detectara el Dockerfile.
7. Plan: Free.
8. Configura usuarios.

Opcion recomendada si el repositorio es publico: en Environment agrega estas variables:

```text
AUDITOR_USERNAME=tu_usuario
AUDITOR_PASSWORD=tu_clave_segura
SECRET_KEY=una_clave_larga_aleatoria
```

Tambien puedes crear varios usuarios con:

```text
AUDITOR_USERS=martin:clave1,cliente:clave2
```

Opcion por archivo si el repositorio es privado: usa `usuarios.txt` y agrega un usuario por linea:

```text
martin:clave1
cliente:clave2
```

Por seguridad, `usuarios.txt` esta en `.gitignore`. Si tu repositorio es privado y quieres subir ese archivo a Render junto con el proyecto, puedes hacer:

```bash
git add -f usuarios.txt
```

Si el repositorio es publico, no subas `usuarios.txt`; usa variables de entorno en Render.

9. Deploy.

Render creara una URL publica como:

```text
https://auditor-fuentes.onrender.com
```

## Notas

- El plan gratis puede dormirse si nadie usa la app.
- La primera carga puede tardar.
- Las capturas usan Playwright/Chromium y consumen mas memoria.
- Cada usuario tiene resultados separados por sesion.
- Si Render reinicia la app, los resultados en memoria se pierden; exporta antes de cerrar.
