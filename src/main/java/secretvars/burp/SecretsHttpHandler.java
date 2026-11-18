package secretvars.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.requests.HttpRequest;
import secretvars.core.Bytes;
import secretvars.core.Http1Rewriter;
import secretvars.core.PlaceholderEngine;
import secretvars.core.SecretStore;
import secretvars.core.Substitution;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Sustituye los marcadores {{secret:NOMBRE}} justo antes de que la petición salga hacia el servidor.
 *
 * Como la modificación se hace en el camino de salida, el contenido del editor (Repeater,
 * Intruder, etc.) no cambia nunca: la pestaña conserva el marcador y cada envío usa el valor
 * vigente en ese momento.
 */
public final class SecretsHttpHandler implements HttpHandler
{
    private final MontoyaApi api;
    private final SecretStore store;
    private final Settings settings;
    /** Avisos ya emitidos, para no inundar el log en ataques de Intruder/Scanner. */
    private final Set<String> warned = ConcurrentHashMap.newKeySet();

    public SecretsHttpHandler(MontoyaApi api, SecretStore store, Settings settings)
    {
        this.api = api;
        this.store = store;
        this.settings = settings;
        store.addListener(warned::clear);
    }

    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request)
    {
        if (!settings.enabled())
        {
            return RequestToBeSentAction.continueWith(request);
        }
        ToolType tool = request.toolSource() == null ? null : request.toolSource().toolType();
        if (!settings.isToolEnabled(tool))
        {
            return RequestToBeSentAction.continueWith(request);
        }

        try
        {
            byte[] raw = request.toByteArray().getBytes();
            if (!PlaceholderEngine.mayContain(raw))
            {
                return RequestToBeSentAction.continueWith(request);
            }

            HttpRequest out;
            Substitution stats;
            List<String> warnings = new ArrayList<>();

            if (isHttp2(request.httpVersion()))
            {
                Http2Result r = rewriteHttp2(request);
                out = r.request;
                stats = r.stats;
            }
            else
            {
                Http1Rewriter.Result r = Http1Rewriter.rewrite(raw, request.bodyOffset(), store::lookup, true);
                stats = r.stats();
                warnings.addAll(r.warnings());
                out = r.changed()
                        ? HttpRequest.httpRequest(request.httpService(), ByteArray.byteArray(r.bytes()))
                        : request;
            }

            report(tool, request, stats, warnings);

            if (!stats.changed())
            {
                return RequestToBeSentAction.continueWith(request);
            }
            store.recordUse(stats.used());
            return RequestToBeSentAction.continueWith(out, request.annotations());
        }
        catch (Throwable t)
        {
            // Ante cualquier fallo, la petición sale intacta: nunca bloquear el tráfico.
            api.logging().logToError("[SecretVars] Error sustituyendo variables en " + safeUrl(request), t);
            return RequestToBeSentAction.continueWith(request);
        }
    }

    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived response)
    {
        return ResponseReceivedAction.continueWith(response);
    }

    // ------------------------------------------------------------------ HTTP/2

    private record Http2Result(HttpRequest request, Substitution stats)
    {
    }

    /**
     * En HTTP/2 se usa la API estructurada (ruta, cabeceras, cuerpo) para no perder la versión
     * del protocolo al reconstruir la petición.
     */
    private Http2Result rewriteHttp2(HttpRequest request)
    {
        HttpRequest out = request;

        Substitution sp = PlaceholderEngine.substitute(request.path(), store::lookup, true);
        if (sp.changed())
        {
            out = out.withPath(sp.output());
        }

        List<HttpHeader> headers = request.headers();
        List<HttpHeader> rebuilt = new ArrayList<>(headers.size());
        List<Substitution> headerStats = new ArrayList<>();
        boolean headersChanged = false;
        boolean renamed = false;
        for (HttpHeader h : headers)
        {
            Substitution sn = PlaceholderEngine.substitute(h.name(), store::lookup, true);
            Substitution sv = PlaceholderEngine.substitute(h.value(), store::lookup, true);
            headerStats.add(sn);
            headerStats.add(sv);
            if (sn.changed() || sv.changed())
            {
                headersChanged = true;
                renamed |= sn.changed();
                rebuilt.add(HttpHeader.httpHeader(sn.output(), sv.output()));
            }
            else
            {
                rebuilt.add(h);
            }
        }

        if (headersChanged)
        {
            if (!renamed && namesAreUnique(headers))
            {
                // Caso habitual: actualizar solo las cabeceras afectadas.
                for (int i = 0; i < headers.size(); i++)
                {
                    if (rebuilt.get(i) != headers.get(i))
                    {
                        out = out.withUpdatedHeader(rebuilt.get(i).name(), rebuilt.get(i).value());
                    }
                }
            }
            else
            {
                // Cabeceras duplicadas o nombres modificados: reconstruir respetando el orden.
                out = out.withRemovedHeaders(headers).withAddedHeaders(rebuilt);
            }
        }

        Substitution sb = PlaceholderEngine.substitute(Bytes.latin1(request.body().getBytes()), store::lookup, true);
        if (sb.changed())
        {
            out = out.withBody(ByteArray.byteArray(Bytes.fromLatin1(sb.output())));
        }

        List<Substitution> all = new ArrayList<>(headerStats);
        all.add(sp);
        all.add(sb);
        return new Http2Result(out, Substitution.mergeStats(all.toArray(new Substitution[0])));
    }

    private static boolean namesAreUnique(List<HttpHeader> headers)
    {
        Set<String> seen = new java.util.HashSet<>();
        for (HttpHeader h : headers)
        {
            if (!seen.add(h.name().toLowerCase(Locale.ROOT)))
            {
                return false;
            }
        }
        return true;
    }

    private static boolean isHttp2(String version)
    {
        return version != null && version.toUpperCase(Locale.ROOT).startsWith("HTTP/2");
    }

    // ------------------------------------------------------------------ registro

    private void report(ToolType tool, HttpRequest request, Substitution stats, List<String> warnings)
    {
        String toolName = tool == null ? "?" : tool.toolName();

        for (String name : stats.missing())
        {
            if (warned.add("missing:" + name))
            {
                api.logging().logToOutput("[SecretVars] AVISO: variable no definida '" + name
                        + "' (" + toolName + ", " + safeUrl(request) + "). El marcador se envía literal.");
            }
        }
        for (String err : stats.errors())
        {
            if (warned.add("error:" + err))
            {
                api.logging().logToOutput("[SecretVars] AVISO: " + err + ". El marcador se envía literal.");
            }
        }
        for (String w : warnings)
        {
            if (warned.add("warn:" + w))
            {
                api.logging().logToOutput("[SecretVars] AVISO: " + w + " (" + safeUrl(request) + ")");
            }
        }

        if (settings.logSubstitutions() && stats.changed())
        {
            // Solo nombres; nunca valores.
            api.logging().logToOutput("[SecretVars] " + toolName + " " + request.method() + " " + safeUrl(request)
                    + " -> " + String.join(", ", stats.used()));
        }
    }

    private static String safeUrl(HttpRequest request)
    {
        try
        {
            // La URL puede contener marcadores, nunca valores (es la petición original).
            return request.url();
        }
        catch (Throwable t)
        {
            return "<url no disponible>";
        }
    }
}
