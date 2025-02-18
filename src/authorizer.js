// authorizer.js
import { CognitoJwtVerifier } from "aws-jwt-verify";

// Vérifiez que vous avez bien un User Pool ID et un client ID en variables d'environnement
const verifier = CognitoJwtVerifier.create({
    userPoolId: process.env.USER_POOL_ID, // ex: eu-west-3_abcd1234
    clientId: process.env.CLIENT_ID,      // ex: 4mvb0blablabla
    tokenUse: "id",                       // "id" ou "access" selon le token à valider
});

export const handler = async (event) => {
    try {
        console.log("Authorizer event:", JSON.stringify(event, null, 2));
        // 1. Récupérer le cookie ou header
        const headers = event.headers || {};
        const cookieHeader = headers.cookie || headers.Cookie;
        if (!cookieHeader) {
            return generateAuthResponse("anonymous", "Deny");
        }

        // 2. Extraire le id_token dans le cookie (ex: id_token=eyJxxx; other_cookie=zzz)
        const tokens = parseCookies(cookieHeader);
        const idToken = tokens["id_token"];
        if (!idToken) {
            return generateAuthResponse("anonymous", "Deny");
        }

        // 3. Vérification du token
        const payload = await verifier.verify(idToken);

        // 4. Autoriser l’accès : on peut utiliser le sub comme principalId
        return generateAuthResponse(payload.sub, "Allow");
    } catch (err) {
        console.error("Error verifying token:", err);
        return generateAuthResponse("anonymous", "Deny");
    }
};

function generateAuthResponse(principalId, effect) {
    // Avec HTTP API, le "payload format" est plus léger qu'avec REST API
    // On peut retourner un objet "IAM Policy" OU un "Simple response" selon la config
    // Voir doc : https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html
    if (effect === "Allow") {
        return {
            isAuthorized: true,
            // Vous pouvez rajouter un context supplémentaire :
            // context: { user: principalId }
        };
    } else {
        return {
            isAuthorized: false,
        };
    }
}

function parseCookies(cookieHeader) {
    return cookieHeader.split(";").reduce((acc, cookie) => {
        const [name, ...rest] = cookie.split("=");
        const trimmedName = name.trim();
        if (!trimmedName) return acc;
        acc[trimmedName] = rest.join("=").trim();
        return acc;
    }, {});
}
