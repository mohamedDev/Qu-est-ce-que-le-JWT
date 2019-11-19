# Qu-est-ce-que-le-JWT

### Résumé

JWT est un jeton permettant d’échanger des informations de manière sécurisée. Ce jeton est composé de trois parties, dont la dernière, la signature, permet d’en vérifier la légitimité. JWT est souvent utilisé pour offrir une authentification stateless au sein d’applications. Plusieurs librairies permettent de manipuler ces tokens évitant ainsi l’écriture d’un code personnel pouvant donner lieu à des vulnérabilités.

## JWT, c’est quoi ?

JWT pour JSON Web Token est une méthode sécurisée d’échange d’informations, décrite par la [RFC 7519](https://tools.ietf.org/html/rfc7519). L’information est échangée sous la forme d’un jeton signé afin de pouvoir en vérifier la légitimité. Ce jeton est compact et peut être inclus dans une URL sans poser de problème.

JWT est couramment utilisé pour implémenter des mécanismes d’authentification stateless pour des SPA (Single Page Application) ou pour des application mobiles.

Un JWT est composé de trois parties, chacune contenant des informations différentes :

*   un header,
*   un payload (les “claims”),
*   la signature.

Le header et le payload sont structurés en JSON. Ces trois parties sont chacunes encodées en base64url, puis concaténées en utilisant des points (“.”).

Le header identifie quel algorithme a été utilisé pour générer la signature, ainsi que le type de token dont il s’agit (souvent JWT, mais le champ a été prévu dans le cas où l’application traite d’autres types d’objet qu’un JWT).

Exemple de header :

    {
      "alg": "HS256",
      "typ": "JWT"
    }

Ici, le header indique que la signature a été générée en utilisant **HMAC-SHA256**.

Le payload est la partie du token qui contient les informations que l’on souhaite transmettre. Ces informations sont appelées “claims”. Il est possible d’ajouter au token les claims que l’on souhaite, mais un certain nombre de claims sont déjà prévus dans les spécifications de JWT.

Par exemple, sub qui identifie le sujet du token (qui le token identifie), iss (issuer) va permettre d’identifier l’émetteur du token ou encore exp qui indique la date d’expiration du token. Il est fortement conseillé d’assigner une valeur à ce dernier champ afin de limiter la durée de vie du token. Si la date d’expiration est dépassée, le token sera rejeté.

Exemple de payload :

    {
        "sub": "John Doe",
        "exp": "1485968105",
        "admin": “true”
    }

La signature est la dernière partie du token. Elle est créée à partir du header et du payload générés et d’un secret. Une signature invalide implique systématiquement le rejet du token.

`HMAC-SHA256(key, header + '.' + payload)`

Une fois ces 3 éléments générés, on peut assembler notre token JWT.  
`token = encodeBase64(header) + '.' + encodeBase64(payload) + '.' + encodeBase64(signature)`

En reprenant les exemples précédents, on arrive au résultat suivant :

**Header:** `{ "alg": "HS256", "typ": "JWT" }`  
**Payload:** `{ "subject": "John Doe", "admin": true, "iat": "1485968105" }`

Token généré :  
`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWJqZWN0IjoiSm9obiBkb2UiLCJhZG1pbiI6dHJ1ZSwiaWF0IjoiMTQ4NTk2ODEwNSJ9.fiSiLFuR4RYuw606Djr2KtQ7y2u-G6OzlHchzklBcd0`

> Header **.** Payload **.** Signature

Maintenant que l’on a notre token, utilisons-le pour nous authentifier !

## S’authentifier avec JWT et Spring Boot

La manière la plus courante d’utiliser un JWT est de s’en servir pour s’authentifier. Le token peut par exemple être utilisé par des applications mobiles ou des applications web de type Single Page Application pour prouver l’identité de l’utilisateur. Le token est alors envoyé avec chaque requête que le client fera auprès de l’application, qui autorisera, ou non, le client à accéder à ses services, suivant la validité du token. Ce type d’authentification, dit stateless, ne stocke pas les sessions utilisateurs dans le contexte de l’application.

Il existe de nombreuses librairies permettant de créer et manipuler les JWT et il est fortement déconseillé de manipuler un JWT avec son propre code. Une liste non exhaustive de librairies est disponible à cette adresse: [https://jwt.io/#libraries-io](https://jwt.io/#libraries-io). Pour cet article, c’est **[jjwt](https://github.com/jwtk/jjwt)** qui a été choisi.

Pour utiliser notre token, il faut tout d’abord le créer. Pour cela, il est nécessaire de s’authentifier avec son login et son mot de passe auprès de l’application afin que celle-ci nous renvoie le token. Une fois le token obtenu, on peut faire appel à nos URL sécurisées en envoyant le token avec notre requête. La méthode la plus courante pour envoyer le token est de l’envoyer à travers l’en-tête HTTP Authorization en tant que Bearer token :  
`Authorization: Bearer 'token'`

Pour traiter le token, on utilise un filter qui va l’extraire du header, le valider puis ajouter au contexte de Spring une authentication correspondant à l’utilisateur pour lequel le token a été émis : notre client est authentifié pour le reste de sa requête.

![jwt-auth](http://blog.ippon.fr/content/images/2017/10/jwt-auth.png)

    @PostMapping(value = {"/auth"}, consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequest authenticationRequest, HttpServletResponse response) {
        Authentication authentication = authenticationService.authenticate(authenticationRequest);

        if(authentication != null && authentication.isAuthenticated()) {
            JwtTokens tokens = jwtTokenService.createTokens(authentication);
            return ResponseEntity.ok().body(tokens);
        }

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication failed");
    }

Le contrôleur est assez simple : il envoie la demande d’authentification à un service et, si l’objet retourné est non null et que le service a validé l’authentification, il demande à un second service de créer notre token JWT à partir de l’objet Authentication. Il retourne ensuite le token créé comme contenu de la réponse.

    @Override
    public String createToken(UserDto user) {
        return Jwts.builder()
            .signWith(SignatureAlgorithm.HS512, secret)
            .setClaims(buildUserClaims(user))
            .setExpiration(getTokenExpirationDate())
            .setIssuedAt(new Date())
            .compact();
    }

    @Override
    public Jws<Claims> validateJwtToken(String token) {
        return Jwts.parser().setSigningKey(secret).parseClaimsJws(token);
    }

Le service JwtTokenService sert à créer notre token ainsi qu’à le valider. Rien de spécial ici, on utilise simplement la librairie jjwt.

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {

        final HttpServletRequest request = (HttpServletRequest) servletRequest;
        final HttpServletResponse response = (HttpServletResponse) servletResponse;

        final Optional<String> token = Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION));

        Authentication authentication;

        if(token.isPresent() && token.get().startsWith(BEARER)) {

            String bearerToken = token.get().substring(BEARER.length()+1);

                try {
                    Jws<Claims> claims = jwtTokenService.validateJwtToken(bearerToken);
                    authentication = authenticationService.getAuthentication(claims);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } catch (ExpiredJwtException exception) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "error.jwt.expired");
                    return;
                } catch (JwtException exception) {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "error.jwt.invalid");
                    return;
                }

        }

        chain.doFilter(servletRequest, servletResponse);
        SecurityContextHolder.getContext().setAuthentication(null);
    }

Le filter est sans doute la partie essentielle de notre chaîne d’authentification. Il va intercepter toutes les requêtes et vérifier la présence d’un JWT, et va ensuite valider le token et récupérer l’objet “authentication” pour l’ajouter au contexte de spring-security. Notre client sera donc authentifié pour la suite de l’exécution de sa requête. À la fin du processus, on supprime l’authentification du contexte.

## Un petit rafraîchissement ?

Le principal inconvénient des JWT est qu’ils ne peuvent pas être révoqués ; en effet, une fois émis, il est possible de valider le token sans appel à la base de données ou au service qui l’aurait émis. En cas de compromission du token, il faut attendre que celui-ci expire (en réalité, il y a d’autres méthodes, j’en parlerai à la fin de l’article).

Afin de limiter le risque de compromission longue, je vais vous proposer dans la suite de cet article un mécanisme se basant sur deux JWT. Le premier token est le même que précédemment et sert donc à nous authentifier à chaque requête via le header “Authorization”. Ce token aura par contre une durée de vie très faible, telle que 5 ou 10mn. Pour pallier cette durée de vie faible, on va émettre un second token avec une durée de vie plus longue (disons 1 mois) qui servira à “rafraîchir” le premier token une fois expiré. Ce token sera créé avec une information en plus, qui sera vérifiée à chaque demande de rafraîchissement de token. Cette information supplémentaire est enregistrée en base et diffère pour chaque utilisateur (salage). En cas de compromission de ce token, il suffit simplement de changer le sel stocké en base de données, ce qui invalidera notre token.

![jwt-auth-2](http://blog.ippon.fr/content/images/2017/10/jwt-auth-2.png)

Si l’on repart du code précédent, il faut faire quelques changements pour adapter notre mécanisme.

Tout d’abord, le contrôleur se voit gratifié d’une nouvelle méthode servant de point d’entrée à la requête de rafraîchissement.

    @PostMapping(value="/auth/refresh",consumes=MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<?> refreshToken(@RequestBody RefreshRequest refreshRequest) {
        try {
            JwtTokens tokens = jwtTokenService.refreshJwtToken(refreshRequest.refreshToken);
            return ResponseEntity.ok().body(tokens);
        } catch (Exception e) {
       return ResponseEntity.status( HttpStatus.UNAUTHORIZED).body( HttpStatus.UNAUTHORIZED.getReasonPhrase());
        }
    }

Ensuite, notre JWTService grossit de quelques méthodes, mais le principal ajout est celui de la validation de notre token de rafraîchissement.

    @Override
    private Jws<Claims> validateJwtRefreshToken(String token) {
        JwtParser parser = Jwts.parser().setSigningKey(secret);
        Jws<Claims> claims = parser.parseClaimsJws(token);

        UserDto user = (UserDto) userService.loadUserByUsername(claims.getBody().getSubject());

        return parser.require(USER_SECRET, user.getUserSecret()).parseClaimsJws(token);
    }

Comme on peut le voir, lors de la validation de notre token, on récupère l’identifiant de l’utilisateur afin de récupérer ses informations en base de données. Une fois les données récupérées, on vérifie que le sel récupéré en base et celui du token sont les mêmes. En cas d’incohérence, notre token est rejeté et la demande de rafraîchissement refusée.

Côté client, il faudra être capable de gérer l’erreur retournée lors de l’expiration du token, puis d’effectuer la requête de rafraîchissement et de relancer la requête précédente avec le nouveau token obtenu.

## Conclusion

JWT est une manière assez simple d’offrir une authentification stateless. Néanmoins, elle souffre de quelques inconvénients pour lesquels il est possible d’apporter des solutions. Cet article vous propose de contourner rapidement et simplement l’un des principaux arguments contre JWT sans trop d’effort. C’est une solution à mi-chemin entre laisser expirer le token JWT et se mettre à OAuth.

Un dernier point très important est à noter. Les données stockées dans les tokens sont simplement encodées, comme annoncé au début de l’article; cela pose donc un problème de confidentialité des données. Il est donc fortement recommandé, même indispensable de n’utiliser JWT qu’à travers une connexion chiffrée (malgré la possibilité de chiffrer l’intégralité du token) !!

PS: Je vous avais parlé d’autres moyens pour invalider un token compromis, donc les voici :

*   Changer le secret de son application (mais invalidera TOUS les tokens de TOUS vos utilisateurs)
*   Tenir une liste de tokens invalidés dans un cache qui sera consulté avant d’effectuer la validation d’un token (ou l'inverse, qui consiste à garder la liste des tokens valides)

Retrouvez le code complet de l’article sur github : [https://github.com/Kaway/jwt-auth](https://github.com/Kaway/jwt-auth)
