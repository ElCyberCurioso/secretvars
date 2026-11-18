package secretvars.core;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reescritura de peticiones HTTP/1.x a nivel de bytes.
 *
 * Solo se tocan los marcadores: el resto de la petición (orden y formato de cabeceras,
 * cabeceras duplicadas, saltos de línea atípicos...) se conserva byte a byte, lo que importa
 * cuando se están probando peticiones deliberadamente malformadas.
 *
 * Content-Length: si el cuerpo cambia de tamaño y existe exactamente una cabecera
 * Content-Length cuyo valor coincidía con el tamaño original del cuerpo, se actualiza.
 * Si el valor no coincidía (manipulación deliberada, p. ej. pruebas de smuggling) o hay
 * varias, no se toca.
 */
public final class Http1Rewriter
{
    private static final Pattern CONTENT_LENGTH =
            Pattern.compile("(?i)(\\n[ \\t]*content-length[ \\t]*:[ \\t]*)(\\d+)");
    private static final Pattern CHUNKED =
            Pattern.compile("(?i)\\ntransfer-encoding[ \\t]*:[^\\n]*chunked");

    private Http1Rewriter()
    {
    }

    public record Result(byte[] bytes, Substitution stats, boolean contentLengthUpdated, List<String> warnings)
    {
        public boolean changed()
        {
            return stats.changed();
        }
    }

    public static Result rewrite(byte[] raw, int bodyOffset, Function<String, String> lookup, boolean applyModifiers)
    {
        if (bodyOffset < 0 || bodyOffset > raw.length)
        {
            bodyOffset = findBodyOffset(raw);
        }

        String head = Bytes.latin1(raw, 0, bodyOffset);
        String body = Bytes.latin1(raw, bodyOffset, raw.length);

        Substitution sh = PlaceholderEngine.substitute(head, lookup, applyModifiers);
        Substitution sb = PlaceholderEngine.substitute(body, lookup, applyModifiers);
        Substitution stats = Substitution.mergeStats(sh, sb);
        List<String> warnings = new ArrayList<>();

        if (!stats.changed())
        {
            return new Result(raw, stats, false, warnings);
        }

        String newHead = sh.output();
        String newBody = sb.output();
        boolean clUpdated = false;

        if (sb.changed())
        {
            int originalLength = raw.length - bodyOffset;
            int newLength = newBody.length(); // cadena de bytes: 1 carácter = 1 byte

            Matcher cl = CONTENT_LENGTH.matcher(newHead);
            List<int[]> spans = new ArrayList<>();
            List<String> values = new ArrayList<>();
            while (cl.find())
            {
                spans.add(new int[]{cl.start(2), cl.end(2)});
                values.add(cl.group(2));
            }

            if (spans.size() == 1)
            {
                if (values.get(0).equals(Integer.toString(originalLength)))
                {
                    int[] s = spans.get(0);
                    newHead = newHead.substring(0, s[0]) + newLength + newHead.substring(s[1]);
                    clUpdated = true;
                }
                else
                {
                    warnings.add("Content-Length no coincidía con el cuerpo original; no se ha modificado");
                }
            }
            else if (spans.size() > 1)
            {
                warnings.add("Varias cabeceras Content-Length; no se han modificado");
            }

            if (CHUNKED.matcher(newHead).find())
            {
                warnings.add("Cuerpo chunked modificado: los tamaños de chunk no se recalculan");
            }
        }

        return new Result(Bytes.fromLatin1(newHead + newBody), stats, clUpdated, warnings);
    }

    /** Fallback por si el offset del cuerpo no es válido. */
    static int findBodyOffset(byte[] raw)
    {
        for (int i = 0; i + 3 < raw.length; i++)
        {
            if (raw[i] == '\r' && raw[i + 1] == '\n' && raw[i + 2] == '\r' && raw[i + 3] == '\n')
            {
                return i + 4;
            }
        }
        for (int i = 0; i + 1 < raw.length; i++)
        {
            if (raw[i] == '\n' && raw[i + 1] == '\n')
            {
                return i + 2;
            }
        }
        return raw.length;
    }
}
