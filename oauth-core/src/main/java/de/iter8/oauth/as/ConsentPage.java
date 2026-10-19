package de.iter8.oauth.as;

import java.net.URI;

import org.springframework.http.HttpHeaders;
import org.springframework.web.util.HtmlUtils;

/**
 * The page that asks the user whether a client may continue to the upstream provider.
 *
 * <p>Without it, any client that publishes a metadata document could send a user here and, if the user had
 * already approved this server's app at the upstream provider, get an authorization code back without the
 * user seeing anything. The upstream provider's own consent belongs to this server's app, not to the client
 * asking, so only this server can ask about the client.
 *
 * <p>Everything about the client comes from a document the client controls, so it is HTML-escaped and
 * labelled for what it is. The client identifier URL is shown prominently because it is the one thing the
 * client cannot fake: it is where the document was fetched from. The display name is shown as the name the
 * client gives itself.
 */
final class ConsentPage {

    /**
     * Response headers for the page. It must never be cached, framed (which would allow clickjacking the
     * Allow button), or leak its URL through a referrer.
     */
    static HttpHeaders headers() {
        HttpHeaders headers = new HttpHeaders();
        headers.setCacheControl("no-store");
        headers.set("X-Frame-Options", "DENY");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Referrer-Policy", "no-referrer");
        // No form-action directive: browsers apply it to the redirect that follows the form post, which goes
        // to the upstream provider or back to the client, and a narrow value would block that redirect.
        headers.set("Content-Security-Policy",
                "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'");
        return headers;
    }

    private ConsentPage() {
    }

    /**
     * @param formAction the absolute URL the decision is posted to
     * @param consentId the identifier of the request awaiting consent
     * @param authorization the request awaiting consent
     * @return the page, with every client-supplied value escaped
     */
    static String render(String formAction, String consentId, PendingAuthorization authorization) {
        StringBuilder details = new StringBuilder()
                .append(row("Sends the result to", code(origin(authorization.redirectUri()))))
                .append(row("Signs you in with", text(authorization.providerId())));
        if (authorization.scope() != null && !authorization.scope().isBlank()) {
            details.append(row("Requested access", code(authorization.scope())));
        }
        if (authorization.resource() != null) {
            details.append(row("To use", code(authorization.resource())));
        }

        return """
                <!doctype html>
                <html lang="en">
                <head>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <title>Allow access?</title>
                <style>
                body { font: 16px/1.5 system-ui, sans-serif; margin: 0; padding: 2rem 1rem; color: #1f2328;
                       background: #f6f8fa; }
                main { max-width: 32rem; margin: 0 auto; background: #fff; border: 1px solid #d0d7de;
                       border-radius: 8px; padding: 1.5rem; }
                h1 { font-size: 1.25rem; margin: 0 0 1rem; }
                .client { font-size: 1.1rem; word-break: break-all; }
                .warning { background: #fff8c5; border-radius: 6px; padding: .75rem; }
                dl { display: grid; grid-template-columns: max-content 1fr; gap: .25rem 1rem; }
                dt { color: #59636e; }
                dd { margin: 0; word-break: break-all; }
                code { font-size: .9em; }
                .buttons { display: flex; gap: .75rem; justify-content: flex-end; margin-top: 1.5rem; }
                button { font: inherit; padding: .5rem 1.25rem; border-radius: 6px; border: 1px solid #d0d7de;
                         background: #f6f8fa; cursor: pointer; }
                button.allow { background: #1f883d; border-color: #1f883d; color: #fff; }
                </style>
                </head>
                <body>
                <main>
                <h1>Allow this app to access your account?</h1>
                <p class="client"><code>%s</code></p>
                <p>It calls itself <strong>%s</strong>.</p>
                <p class="warning">Only allow this if you recognize the address above and started this request
                yourself. If you were sent here by a link you did not expect, deny it.</p>
                <dl>
                %s</dl>
                <form method="post" action="%s">
                <input type="hidden" name="consent_id" value="%s">
                <div class="buttons">
                <button type="submit" name="decision" value="deny">Deny</button>
                <button type="submit" name="decision" value="allow" class="allow">Allow</button>
                </div>
                </form>
                </main>
                </body>
                </html>
                """.formatted(text(authorization.clientId()), text(authorization.clientName()), details,
                text(formAction), text(consentId));
    }

    private static String row(String label, String valueHtml) {
        return "<dt>" + text(label) + "</dt><dd>" + valueHtml + "</dd>\n";
    }

    private static String code(String value) {
        return "<code>" + text(value) + "</code>";
    }

    private static String text(String value) {
        return (value == null) ? "" : HtmlUtils.htmlEscape(value);
    }

    /**
     * Where the authorization result goes, reduced to scheme and host for http(s) URLs, which is the part a
     * user can judge. Other schemes, such as a desktop app's custom scheme, are shown in full.
     */
    private static String origin(String redirectUri) {
        try {
            URI uri = URI.create(redirectUri);
            if (uri.getAuthority() != null
                    && ("https".equals(uri.getScheme()) || "http".equals(uri.getScheme()))) {
                return uri.getScheme() + "://" + uri.getAuthority();
            }
        }
        catch (IllegalArgumentException malformed) {
            // Fall through and show it as given.
        }
        return redirectUri;
    }
}
