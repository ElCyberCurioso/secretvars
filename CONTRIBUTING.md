# Contribuir a SecretVars

¡Gracias por tu interés! Estas son las pautas para que los cambios se integren sin fricción.

## Antes de empezar

- Para errores, abre un issue con la plantilla **Bug**. Para ideas nuevas, usa **Propuesta** y espera a
  comentarlo antes de dedicarle tiempo a un PR grande.
- Las vulnerabilidades **no** se reportan en issues: sigue [SECURITY.md](SECURITY.md).

## Entorno

- JDK 17 o superior.
- No hace falta instalar Gradle: usa `./gradlew` (o `gradlew.bat` en Windows).

```bash
./gradlew build      # compila, ejecuta las pruebas y genera el JAR en build/libs/
```

Para probar en Burp: `Extensions › Installed › Add` con el JAR de `build/libs/`. Tras recompilar, en la
lista de extensiones haz *Ctrl+clic* (*Cmd+clic* en macOS) en la casilla *Loaded* para recargarla.

## Organización del código

| Paquete              | Contenido                                                              | Depende de Burp |
|----------------------|------------------------------------------------------------------------|-----------------|
| `secretvars.core`    | Motor de sustitución, reescritura HTTP/1, almacén y serialización      | No              |
| `secretvars.burp`    | `HttpHandler`, menú contextual, pestaña del editor, ajustes            | Sí              |
| `secretvars.ui`      | Pestaña de gestión y diálogo de edición                                | Sí (`ToolType`) |

Mantén la lógica en `core` siempre que puedas: es la parte que se prueba sin Burp.

## Pruebas

Las pruebas son programas autocontenidos (sin JUnit) que terminan con código de salida distinto de 0 si algo
falla:

- `CoreTests`: motor, modificadores, Content-Length, almacén y serialización.
- `HandlerSimulation`: el `HttpHandler` real contra una API Montoya simulada con proxies dinámicos.
- `RenderPanel`: renderiza la pestaña de gestión a PNG para revisar la maquetación
  (`java -Djava.awt.headless=true ... secretvars.ui.RenderPanel salida.png`).

Todo cambio de comportamiento debe venir con su prueba en `CoreTests` o `HandlerSimulation`.

## Compatibilidad con Burp

- El código se compila con `--release 17`.
- Evita usar métodos de la API Montoya añadidos recientemente sin protegerlos: en versiones antiguas de
  Burp provocan `NoSuchMethodError` al cargar o al ejecutarse. Si los necesitas, envuélvelos en
  `try/catch (Throwable)` con alternativa, como se hace con `swingUtils()` y `applyThemeToComponent()`.
- No referencies constantes nuevas de enums de la API (p. ej. `ToolType`) de forma estática; recórrelos con
  `values()`.

## Estilo

- Llaves en línea propia, indentación de 4 espacios (ver `.editorconfig`).
- Comentarios y textos de interfaz en español.
- **Nunca** escribas valores de secretos en logs, excepciones ni `toString()`.

## Pull requests

1. Crea una rama desde `main` (`fix/...`, `feat/...`).
2. Asegúrate de que `./gradlew build` pasa.
3. Añade la entrada en la sección `[Unreleased]` de `CHANGELOG.md`.
4. Rellena la plantilla del PR.
