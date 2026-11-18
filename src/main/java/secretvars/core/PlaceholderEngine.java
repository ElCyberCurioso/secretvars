package secretvars.core;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Motor de sustitución de marcadores.
 *
 * Sintaxis:   {{secret:NOMBRE}}
 *             {{secret:NOMBRE|mod1|mod2}}   (los modificadores se aplican de izquierda a derecha)
 *
 * Modificadores:
 *   url     -> percent-encoding de todo lo que no sea [A-Za-z0-9-_.~]
 *   b64     -> Base64 estándar
 *   b64url  -> Base64 URL-safe sin padding (estilo JWT)
 *   hex     -> hexadecimal en minúsculas
 *   json    -> escapado para insertar dentro de una cadena JSON
 *
 * El valor se inserta codificado en UTF-8. Los marcadores con variable no definida o con
 * modificadores desconocidos se dejan intactos y se informan en el resultado.
 */
public final class PlaceholderEngine
{
    public static final String PREFIX = "{{secret:";
    private static final byte[] PREFIX_BYTES = PREFIX.getBytes(StandardCharsets.ISO_8859_1);

    public static final Pattern NAME_PATTERN = Pattern.compile("[A-Za-z0-9_.\\-]+");
    public static final Pattern PLACEHOLDER = Pattern.compile(
            "\\{\\{secret:([A-Za-z0-9_.\\-]+)((?:\\|[A-Za-z0-9]+)*)\\}\\}");

    public static final String[] MODIFIERS = {"url", "b64", "b64url", "hex", "json"};

    private PlaceholderEngine()
    {
    }

    public static String placeholder(String name)
    {
        return PREFIX + name + "}}";
    }

    public static boolean isValidName(String name)
    {
        return name != null && NAME_PATTERN.matcher(name).matches();
    }

    /** Comprobación barata previa a la expresión regular. */
    public static boolean mayContain(byte[] data)
    {
        return data != null && Bytes.indexOf(data, PREFIX_BYTES) >= 0;
    }

    public static boolean mayContain(String byteString)
    {
        return byteString != null && byteString.contains(PREFIX);
    }

    /**
     * Sustituye los marcadores de una cadena de bytes.
     *
     * @param input          cadena de bytes (vista ISO-8859-1)
     * @param lookup         nombre -> valor Unicode, o null si no existe
     * @param applyModifiers false para vistas enmascaradas (el valor se inserta tal cual)
     */
    public static Substitution substitute(String input, Function<String, String> lookup, boolean applyModifiers)
    {
        if (!mayContain(input))
        {
            return Substitution.unchanged(input);
        }

        Matcher m = PLACEHOLDER.matcher(input);
        StringBuilder out = new StringBuilder(input.length() + 64);
        Set<String> used = new LinkedHashSet<>();
        Set<String> missing = new LinkedHashSet<>();
        Set<String> errors = new LinkedHashSet<>();
        int count = 0;
        int last = 0;

        while (m.find())
        {
            String name = m.group(1);
            String mods = m.group(2);
            String value = lookup.apply(name);

            out.append(input, last, m.start());
            last = m.end();

            if (value == null)
            {
                missing.add(name);
                out.append(m.group());
                continue;
            }

            try
            {
                byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
                if (applyModifiers && !mods.isEmpty())
                {
                    for (String mod : mods.substring(1).split("\\|"))
                    {
                        bytes = applyModifier(mod.toLowerCase(Locale.ROOT), bytes);
                    }
                }
                out.append(Bytes.latin1(bytes));
                used.add(name);
                count++;
            }
            catch (IllegalArgumentException e)
            {
                errors.add(m.group() + ": " + e.getMessage());
                out.append(m.group());
            }
        }
        out.append(input, last, input.length());

        return new Substitution(count > 0 ? out.toString() : input, count, used, missing, errors);
    }

    static byte[] applyModifier(String mod, byte[] in)
    {
        switch (mod)
        {
            case "url":
                return urlEncode(in);
            case "b64":
                return Base64.getEncoder().encode(in);
            case "b64url":
                return Base64.getUrlEncoder().withoutPadding().encode(in);
            case "hex":
                return hex(in);
            case "json":
                return jsonEscape(in);
            default:
                throw new IllegalArgumentException("modificador desconocido '" + mod + "'");
        }
    }

    private static byte[] urlEncode(byte[] in)
    {
        StringBuilder sb = new StringBuilder(in.length * 3);
        for (byte b : in)
        {
            int c = b & 0xff;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '_' || c == '.' || c == '~')
            {
                sb.append((char) c);
            }
            else
            {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xf, 16)));
            }
        }
        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] hex(byte[] in)
    {
        StringBuilder sb = new StringBuilder(in.length * 2);
        for (byte b : in)
        {
            sb.append(Character.forDigit((b >> 4) & 0xf, 16)).append(Character.forDigit(b & 0xf, 16));
        }
        return sb.toString().getBytes(StandardCharsets.ISO_8859_1);
    }

    private static byte[] jsonEscape(byte[] in)
    {
        String s = new String(in, StandardCharsets.UTF_8);
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++)
        {
            char c = s.charAt(i);
            switch (c)
            {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                default ->
                {
                    if (c < 0x20)
                    {
                        sb.append(String.format("\\u%04x", (int) c));
                    }
                    else
                    {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }
}
