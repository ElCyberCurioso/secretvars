# Política de seguridad

## Versiones soportadas

Solo se corrigen vulnerabilidades en la última versión publicada en
[Releases](https://github.com/ElCyberCurioso/secretvars/releases).

## Cómo informar de una vulnerabilidad

**No abras un issue público.** Usa el reporte privado de GitHub:
pestaña *Security › Report a vulnerability* de este repositorio.

Incluye, si es posible:

- Versión de SecretVars, de Burp Suite (edición y número) y del sistema operativo.
- Descripción del problema e impacto.
- Pasos para reproducirlo o prueba de concepto.

**No incluyas secretos reales** (tokens, contraseñas, ficheros `.burp` de clientes) en el reporte. Sustitúyelos
por valores de ejemplo.

Recibirás una primera respuesta en un plazo razonable; si se confirma, se publicará una versión corregida y
se te dará crédito si lo deseas.

## Modelo de seguridad

Qué protege la extensión y qué no:

| Aspecto                                   | Comportamiento                                                        |
|-------------------------------------------|-----------------------------------------------------------------------|
| Editores (Repeater, Intruder...)          | Solo contienen el marcador `{{secret:NOMBRE}}`, nunca el valor        |
| Logs de la extensión (Output / Errors)    | Solo nombres de variable, nunca valores                               |
| Tabla de secretos y vista resuelta        | Valores enmascarados por defecto                                      |
| Almacenamiento (proyecto y preferencias)  | **Sin cifrar**. Protege el fichero `.burp` y tu perfil de usuario     |
| Peticiones enviadas (Logger, historial)   | **Contienen el valor real**, porque es lo que recibe el servidor       |

Fuera del alcance: la confidencialidad de los ficheros de proyecto y de las preferencias de Burp, y el
contenido de las respuestas del servidor (que puede reflejar el secreto).
