package secretvars.core;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;

/**
 * Utilidades de conversión entre bytes y "cadenas de bytes".
 *
 * Una "cadena de bytes" es un String en el que cada carácter representa exactamente
 * un byte (0-255), es decir, una vista ISO-8859-1 de los bytes. Trabajar así garantiza
 * que la reescritura de peticiones no altera ningún byte que no sea un marcador.
 */
public final class Bytes
{
    private Bytes()
    {
    }

    public static String latin1(byte[] data)
    {
        return new String(data, StandardCharsets.ISO_8859_1);
    }

    public static String latin1(byte[] data, int from, int to)
    {
        return new String(data, from, to - from, StandardCharsets.ISO_8859_1);
    }

    public static byte[] fromLatin1(String byteString)
    {
        return byteString.getBytes(StandardCharsets.ISO_8859_1);
    }

    /** Valor Unicode -> cadena de bytes con su codificación UTF-8. */
    public static String utf8AsLatin1(String value)
    {
        return latin1(value.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Convierte bytes seleccionados en un editor en el valor de un secreto.
     * Si son UTF-8 válido se decodifican como UTF-8 (al reinsertarlos se obtienen los mismos bytes);
     * si no, se usa ISO-8859-1.
     */
    public static String decodeSelection(byte[] data)
    {
        try
        {
            return StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(data))
                    .toString();
        }
        catch (CharacterCodingException e)
        {
            return latin1(data);
        }
    }

    public static int indexOf(byte[] haystack, byte[] needle)
    {
        if (needle.length == 0)
        {
            return 0;
        }
        outer:
        for (int i = 0; i <= haystack.length - needle.length; i++)
        {
            for (int j = 0; j < needle.length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    public static byte[] splice(byte[] data, int start, int end, byte[] replacement)
    {
        byte[] out = new byte[data.length - (end - start) + replacement.length];
        System.arraycopy(data, 0, out, 0, start);
        System.arraycopy(replacement, 0, out, start, replacement.length);
        System.arraycopy(data, end, out, start + replacement.length, data.length - end);
        return out;
    }
}
