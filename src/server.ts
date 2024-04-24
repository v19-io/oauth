export interface Client {
  id: string;
  secret: string | null;
  redirectUris: URL[];
  type: "confidential" | "public";
}

export interface AuthorizationServerConfig {
  getClient: (id: string) => Promise<Client | undefined>;
  supportsClientCredentialsFlow: (client: Client) => Promise<boolean>;
  supportsImplicitFlow: (client: Client) => Promise<boolean>;
  supportsPasswordFlow: (client: Client) => Promise<boolean>;
  getAuthorizationCode: (code: string) => Promise<Token | undefined>;
  deleteAuthorizationCode: (code: string) => Promise<void>;
  getAccessToken: (token: string) => Promise<Token | undefined>;
  deleteAccessToken: (token: string) => Promise<void>;
  getRefreshToken: (token: string) => Promise<Token | undefined>;
  deleteRefreshToken: (token: string) => Promise<void>;
  invalidateAuthorization: (id: string) => Promise<void>;
  isValidScope: (client: Client, scope: string) => Promise<boolean>;
  scopeEqualOrNarrower: (
    client: Client,
    scope: string,
    scopes: string[],
  ) => Promise<boolean>;
  issueAuthorization: (
    client: Client,
    scopes: string[],
    redirectUri: URL,
  ) => Promise<Authorization>;
  authorizePasswordFor: (
    client: Client,
    username: string,
    password: string,
    scopes: string[],
  ) => Promise<Authorization | null>;
  getAuthorization: (id: string) => Promise<Authorization | undefined>;
  issueToken: (
    type: TokenType,
    client: Client,
    scopes: string[],
    expires: Date,
    authorization: string | "client_credentials",
  ) => Promise<Token>;
  authorizeClientCredentialsFor: (
    client: Client,
    scope: string,
  ) => Promise<boolean>;
  accessTokenLifetime: number;
  refreshTokenLifetime: number;
  realm: string;
}

export const SEVEN_DAYS = 7 * 24 * 60 * 60;
export const THIRTY_DAYS = 30 * 24 * 60 * 60;

export interface Token {
  type: TokenType;
  value: string;
  expires: Date;
  scopes: string[];
  authorization: string;
}

export interface Authorization {
  id: string;
  scopes: string[];
  redirectUri: URL | null;
  clientId: string;
}

export type ResponseType = "code" | "token";
export type ErrorCode =
  | "invalid_request"
  | "unauthorized_client"
  | "access_denied"
  | "unsupported_response_type"
  | "invalid_scope"
  | "server_error"
  | "temporarily_unavailable";
export type RedirectUriError = "invalid_redirect_uri" | "missing_redirect_uri";
export type TokenType = "access_token" | "refresh_token" | "authorization_code";
export type GrantType =
  | "authorization_code"
  | "client_credentials"
  | "refresh_token"
  | "password";

export class AuthorizationContext {
  constructor(
    public readonly client: Client,
    public readonly redirectUri: URL,
    public readonly state: string,
    public readonly responseType: ResponseType,
    public readonly scopes: string[],
  ) {}
}

export class AuthorizationServer {
  constructor(private config: AuthorizationServerConfig) {
    if (config.accessTokenLifetime < 0) {
      throw new Error("accessTokenLifetime must be positive");
    }
    if (config.accessTokenLifetime > 30 * 24 * 60 * 60) {
      throw new Error("accessTokenLifetime must be less than 30 days");
    }
    if (config.refreshTokenLifetime < 0) {
      throw new Error("refreshTokenLifetime must be positive");
    }
    if (config.refreshTokenLifetime > 365 * 24 * 60 * 60) {
      throw new Error("refreshTokenLifetime must be less than 365 days");
    }
  }

  async getAuthorizationContext(
    request: Request,
  ): Promise<Response | AuthorizationContext | RedirectUriError> {
    const params = new URL(request.url).searchParams;

    // check redirect URI
    const redirectUriRaw = params.get("redirect_uri");
    if (!redirectUriRaw) {
      return "missing_redirect_uri";
    }
    if (!URL.canParse(redirectUriRaw)) {
      return "invalid_redirect_uri";
    }
    const redirectUri = new URL(redirectUriRaw);
    const clientId = params.get("client_id");
    if (!clientId) {
      return "invalid_redirect_uri";
    }
    let client;
    try {
      client = await this.config.getClient(clientId);
    } catch (e) {
      return "invalid_redirect_uri";
    }
    if (!client) {
      return "invalid_redirect_uri";
    }
    const redirectUriString = redirectUri.toString();
    if (
      !client.redirectUris.some((uri) => uri.toString() === redirectUriString)
    ) {
      return "invalid_redirect_uri";
    }

    // check state
    const state = params.get("state") ?? "";
    const responseType = params.get("response_type");
    const errorInHash = responseType === "token";
    // check response type
    if (responseType !== "code" && responseType !== "token") {
      return this.redirectErrorResponse(
        redirectUri,
        state,
        "unsupported_response_type",
        { hash: errorInHash },
      );
    }
    if (!state) {
      return this.redirectErrorResponse(redirectUri, state, "invalid_request", {
        hash: errorInHash,
      });
    }

    try {
      if (
        responseType === "token" &&
        !(await this.config.supportsImplicitFlow(client))
      ) {
        return this.redirectErrorResponse(
          redirectUri,
          state,
          "unsupported_response_type",
          { hash: errorInHash },
        );
      }
    } catch (e) {
      return this.redirectErrorResponse(redirectUri, state, "server_error", {
        hash: errorInHash,
      });
    }

    // check valid scopes
    const scope = params.get("scope");
    const scopes = scope ? scope.split(" ") : [];
    for (const scope of scopes) {
      try {
        if (!(await this.config.isValidScope(client, scope))) {
          return this.redirectErrorResponse(
            redirectUri,
            state,
            "invalid_scope",
            {
              hash: errorInHash,
            },
          );
        }
      } catch (e) {
        return this.redirectErrorResponse(redirectUri, state, "server_error", {
          hash: errorInHash,
        });
      }
    }

    return new AuthorizationContext(
      client,
      redirectUri,
      state,
      responseType,
      scopes,
    );
  }

  async authorizationEndpoint(
    request: Request,
    scopes: string[],
  ): Promise<Response | RedirectUriError> {
    const context = await this.getAuthorizationContext(request);
    if (context instanceof Response) {
      return context;
    }
    if (typeof context === "string") {
      return context;
    }

    const authorization = await this.config.issueAuthorization(
      context.client,
      scopes,
      context.redirectUri,
    );
    // generate authorization code
    if (context.responseType === "code") {
      const code = await this.config.issueToken(
        "authorization_code",
        context.client,
        scopes,
        new Date(Date.now() + 10 * 60 * 1000),
        authorization.id,
      );
      const url = new URL(context.redirectUri.toString());
      url.searchParams.set("code", code.value);
      url.searchParams.set("state", context.state);
      return Response.redirect(url, 302);
    } else if (context.responseType === "token") {
      const accessToken = await this.config.issueToken(
        "access_token",
        context.client,
        scopes,
        new Date(Date.now() + this.config.accessTokenLifetime * 1000),
        authorization.id,
      );
      const url = new URL(context.redirectUri.toString());
      const hash = new URLSearchParams();
      hash.set("access_token", accessToken.value);
      hash.set("token_type", "Bearer");
      hash.set("expires_in", this.config.accessTokenLifetime.toString());
      hash.set("scope", scopes.join(" "));
      hash.set("state", context.state);
      url.hash = hash.toString();
      return Response.redirect(url, 302);
    }

    // should never reach here
    throw new Error("Invalid response type");
  }

  async tokenEndpoint(request: Request): Promise<Response> {
    if (request.method !== "POST") {
      return new Response(null, {
        status: 405,
        headers: {
          Allow: "POST",
          "Cache-Control": "no-store",
          Pragma: "no-cache",
        },
      });
    }
    const body = new URLSearchParams(await request.text());
    const grantType = body.get("grant_type");
    if (!grantType) {
      return Response.json(
        {
          error: "invalid_request",
          error_description: "Missing grant_type",
        },
        {
          status: 400,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
    const client = await this.authenticateClient(request, body);
    if (client instanceof Response) {
      return client;
    }
    if (grantType === "authorization_code") {
      return await this.authorizationCodeGrant(body, client);
    } else if (
      grantType === "client_credentials" &&
      client.type === "confidential" &&
      (await this.config.supportsClientCredentialsFlow(client))
    ) {
      return await this.clientCredentialsGrant(body, client);
    } else if (grantType === "refresh_token") {
      return await this.refreshTokenGrant(body, client);
    } else if (
      grantType === "password" &&
      (await this.config.supportsPasswordFlow(client))
    ) {
      return await this.passwordGrant(body, client);
    } else {
      return Response.json(
        {
          error: "unsupported_grant_type",
        },
        {
          status: 400,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
  }

  private async authorizationCodeGrant(
    body: URLSearchParams,
    client: Client,
  ): Promise<Response> {
    const code = body.get("code");
    if (!code) {
      return Response.json(
        {
          error: "invalid_request",
          error_description: "Missing code",
        },
        {
          status: 400,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
    const redirectUri = body.get("redirect_uri");
    if (!redirectUri) {
      return Response.json(
        {
          error: "invalid_request",
          error_description: "Missing redirect_uri",
        },
        {
          status: 400,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
    try {
      const token = await this.config.getAuthorizationCode(code);
      if (!token) {
        return Response.json(
          {
            error: "invalid_grant",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      if (token.expires < new Date()) {
        await this.config.deleteAuthorizationCode(code);
        return Response.json(
          {
            error: "invalid_grant",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      const authorization = await this.config.getAuthorization(
        token.authorization,
      );
      if (
        !authorization ||
        (authorization.redirectUri &&
          authorization.redirectUri.toString() !== redirectUri)
      ) {
        return Response.json(
          {
            error: "invalid_grant",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      if (authorization.clientId !== client.id) {
        return Response.json(
          {
            error: "invalid_grant",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      const accessToken = await this.config.issueToken(
        "access_token",
        client,
        authorization.scopes,
        new Date(Date.now() + this.config.accessTokenLifetime * 1000),
        token.authorization,
      );
      const refreshToken = await this.config.issueToken(
        "refresh_token",
        client,
        authorization.scopes,
        new Date(Date.now() + this.config.refreshTokenLifetime * 1000),
        token.authorization,
      );
      await this.config.deleteAuthorizationCode(code);
      return Response.json(
        {
          access_token: accessToken.value,
          token_type: "Bearer",
          expires_in: this.config.accessTokenLifetime,
          refresh_token: refreshToken.value,
          scope: authorization.scopes.join(" "),
        },
        {
          status: 200,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    } catch (e) {
      return Response.json(
        {
          error: "server_error",
        },
        {
          status: 500,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
  }

  private async clientCredentialsGrant(
    body: URLSearchParams,
    client: Client,
  ): Promise<Response> {
    const scopes = body.get("scope")?.split(" ") ?? [];
    for (const scope of scopes) {
      if (!(await this.config.isValidScope(client, scope))) {
        return Response.json(
          {
            error: "invalid_scope",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
    }
    try {
      for (const scope of scopes) {
        if (!(await this.config.authorizeClientCredentialsFor(client, scope))) {
          return Response.json(
            {
              error: "access_denied",
            },
            {
              status: 400,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
      }
      const accessToken = await this.config.issueToken(
        "access_token",
        client,
        scopes,
        new Date(Date.now() + this.config.accessTokenLifetime * 1000),
        "client_credentials",
      );
      return Response.json(
        {
          access_token: accessToken.value,
          token_type: "Bearer",
          expires_in: this.config.accessTokenLifetime,
          scope: scopes.join(" "),
        },
        {
          status: 200,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    } catch (e) {
      return Response.json(
        {
          error: "server_error",
        },
        {
          status: 500,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
  }

  private async refreshTokenGrant(
    body: URLSearchParams,
    client: Client,
  ): Promise<Response> {
    const refreshToken = body.get("refresh_token");
    if (!refreshToken) {
      return Response.json(
        {
          error: "invalid_request",
          error_description: "Missing refresh_token",
        },
        {
          status: 400,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
    try {
      const token = await this.config.getRefreshToken(refreshToken);
      if (!token) {
        return Response.json(
          {
            error: "invalid_grant",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      if (token.expires < new Date()) {
        await this.config.deleteRefreshToken(refreshToken);
        return Response.json(
          {
            error: "invalid_grant",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      const authorization = await this.config.getAuthorization(
        token.authorization,
      );
      if (!authorization) {
        return Response.json(
          {
            error: "invalid_grant",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      if (authorization.clientId !== client.id) {
        return Response.json(
          {
            error: "invalid_grant",
          },
          {
            status: 400,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      const scopes = body.get("scope")?.split(" ") ?? authorization.scopes;
      for (const scope of scopes) {
        if (!(await this.config.isValidScope(client, scope))) {
          return Response.json(
            {
              error: "invalid_scope",
            },
            {
              status: 400,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
      }
      for (const scope of scopes) {
        if (
          !authorization.scopes.includes(scope) &&
          !(await this.config.scopeEqualOrNarrower(
            client,
            scope,
            authorization.scopes,
          ))
        ) {
          return Response.json(
            {
              error: "invalid_scope",
            },
            {
              status: 400,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
      }
      const accessToken = await this.config.issueToken(
        "access_token",
        client,
        scopes,
        new Date(Date.now() + this.config.accessTokenLifetime * 1000),
        token.authorization,
      );
      const newRefreshToken = await this.config.issueToken(
        "refresh_token",
        client,
        authorization.scopes,
        new Date(Date.now() + this.config.refreshTokenLifetime * 1000),
        token.authorization,
      );
      await this.config.deleteRefreshToken(refreshToken);
      return Response.json(
        {
          access_token: accessToken.value,
          token_type: "Bearer",
          expires_in: this.config.accessTokenLifetime,
          refresh_token: newRefreshToken.value,
          scope: scopes.join(" "),
        },
        {
          status: 200,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    } catch (e) {
      return Response.json(
        {
          error: "server_error",
        },
        {
          status: 500,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
  }

  private async passwordGrant(
    body: URLSearchParams,
    client: Client,
  ): Promise<Response> {
    const username = body.get("username");
    const password = body.get("password");
    if (!username || !password) {
      return Response.json(
        {
          error: "invalid_request",
          error_description: "Missing username or password",
        },
        {
          status: 400,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
    const scopes = body.get("scope")?.split(" ") ?? [];
    try {
      for (const scope of scopes) {
        if (!(await this.config.isValidScope(client, scope))) {
          return Response.json(
            {
              error: "invalid_scope",
            },
            {
              status: 400,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
      }
      const authorization = await this.config.authorizePasswordFor(
        client,
        username,
        password,
        scopes,
      );
      if (!authorization) {
        return Response.json(
          {
            error: "access_denied",
          },
          {
            status: 401,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      const accessToken = await this.config.issueToken(
        "access_token",
        client,
        scopes,
        new Date(Date.now() + this.config.accessTokenLifetime * 1000),
        authorization.id,
      );
      const refreshToken = await this.config.issueToken(
        "refresh_token",
        client,
        scopes,
        new Date(Date.now() + this.config.refreshTokenLifetime * 1000),
        authorization.id,
      );
      return Response.json(
        {
          access_token: accessToken.value,
          token_type: "Bearer",
          expires_in: this.config.accessTokenLifetime,
          refresh_token: refreshToken.value,
          scope: scopes.join(" "),
        },
        {
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    } catch (e) {
      return Response.json(
        {
          error: "server_error",
        },
        {
          status: 500,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
  }

  private async authenticateClient(
    request: Request,
    body: URLSearchParams,
  ): Promise<Client | Response> {
    const basic = request.headers.get("Authorization");
    if (basic) {
      const parts = basic.split(" ");
      if (parts.length !== 2) {
        return Response.json(
          {
            error: "invalid_request",
            error_description: "Invalid Authorization header",
          },
          {
            status: 400,
            headers: {
              "WWW-Authenticate": `Basic realm="${this.config.realm}"`,
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      if (parts[0].toLowerCase() !== "basic") {
        return Response.json(
          {
            error: "invalid_request",
            error_description: "Invalid Authorization header",
          },
          {
            status: 400,
            headers: {
              "WWW-Authenticate": `Basic realm="${this.config.realm}"`,
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      const decoded = atob(parts[1]);
      const [id, secret] = decoded.split(":");
      if (!id) {
        return Response.json(
          {
            error: "invalid_request",
            error_description: "Invalid Authorization header",
          },
          {
            status: 400,
            headers: {
              "WWW-Authenticate": `Basic realm="${this.config.realm}"`,
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      try {
        const client = await this.config.getClient(id);
        if (!client) {
          return Response.json(
            {
              error: "invalid_client",
            },
            {
              status: 401,
              headers: {
                "WWW-Authenticate": `Basic realm="${this.config.realm}"`,
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
        if (client.type === "confidential" && !secret) {
          return Response.json(
            {
              error: "invalid_request",
              error_description: "Invalid Authorization header",
            },
            {
              status: 400,
              headers: {
                "WWW-Authenticate": `Basic realm="${this.config.realm}"`,
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
        if (client.type === "confidential" && client.secret !== secret) {
          return Response.json(
            {
              error: "invalid_client",
            },
            {
              status: 401,
              headers: {
                "WWW-Authenticate": `Basic realm="${this.config.realm}"`,
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
        return client;
      } catch (e) {
        return Response.json(
          {
            error: "server_error",
          },
          {
            status: 500,
            headers: {
              "WWW-Authenticate": `Basic realm="${this.config.realm}"`,
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
    } else {
      const clientId = body.get("client_id");
      const clientSecret = body.get("client_secret");
      if (!clientId) {
        return Response.json(
          {
            error: "invalid_client",
          },
          {
            status: 401,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
      try {
        const client = await this.config.getClient(clientId);
        if (!client) {
          return Response.json(
            {
              error: "invalid_client",
            },
            {
              status: 401,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
        if (client.type === "confidential" && !clientSecret) {
          return Response.json(
            {
              error: "invalid_client",
            },
            {
              status: 401,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
        if (client.type === "confidential" && client.secret !== clientSecret) {
          return Response.json(
            {
              error: "invalid_client",
            },
            {
              status: 401,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
        return client;
      } catch (e) {
        return Response.json(
          {
            error: "server_error",
          },
          {
            status: 500,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          },
        );
      }
    }
  }

  private redirectErrorResponse(
    redirect: URL,
    state: string,
    error: ErrorCode,
    options: {
      description?: string;
      uri?: string;
      hash?: boolean;
    } = {},
  ): Response {
    const url = new URL(redirect.toString());
    if (options.hash) {
      const hash = new URLSearchParams();
      hash.set("error", error);
      hash.set("state", state);
      if (options.description) {
        hash.set("error_description", options.description);
      }
      if (options.uri) {
        hash.set("error_uri", options.uri);
      }
      url.hash = hash.toString();
    } else {
      url.searchParams.set("error", error);
      url.searchParams.set("state", state);
      if (options.description) {
        url.searchParams.set("error_description", options.description);
      }
      if (options.uri) {
        url.searchParams.set("error_uri", options.uri);
      }
    }
    return Response.redirect(url, 302);
  }

  isValidRedirectUri(uri: string): boolean {
    if (!URL.canParse(uri)) {
      return false;
    }
    const url = new URL(uri);
    return url.hash === "";
  }

  async revocationEndpoint(request: Request): Promise<Response> {
    if (request.method !== "POST") {
      return new Response(null, {
        status: 405,
        headers: {
          Allow: "POST",
          "Cache-Control": "no-store",
          Pragma: "no-cache",
        },
      });
    }
    const body = new URLSearchParams(await request.text());
    const token = body.get("token");
    const tokenTypeHint = body.get("token_type_hint");
    if (!token) {
      return Response.json(
        {
          error: "invalid_request",
          error_description: "Missing token",
        },
        {
          status: 400,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
    const client = await this.authenticateClient(request, body);
    if (client instanceof Response) {
      return client;
    }
    try {
      const accessToken = await this.config.getAccessToken(token);
      if (accessToken) {
        const authorization = await this.config.getAuthorization(
          accessToken.authorization,
        );
        if (authorization && authorization.clientId === client.id) {
          await this.config.deleteAccessToken(token);
          return new Response(null, {
            status: 200,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          });
        } else {
          return Response.json(
            {
              error: "unauthorized_client",
            },
            {
              status: 401,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
      }
      const refreshToken = await this.config.getRefreshToken(token);
      if (refreshToken) {
        const authorization = await this.config.getAuthorization(
          refreshToken.authorization,
        );
        if (authorization && authorization.clientId === client.id) {
          await this.config.deleteRefreshToken(token);
          await this.config.invalidateAuthorization(authorization.id);
          return new Response(null, {
            status: 200,
            headers: {
              "Cache-Control": "no-store",
              Pragma: "no-cache",
            },
          });
        } else {
          return Response.json(
            {
              error: "unauthorized_client",
            },
            {
              status: 401,
              headers: {
                "Cache-Control": "no-store",
                Pragma: "no-cache",
              },
            },
          );
        }
      }
      return new Response(null, {
        status: 200,
        headers: {
          "Cache-Control": "no-store",
          Pragma: "no-cache",
        },
      });
    } catch (e) {
      return Response.json(
        {
          error: "server_error",
        },
        {
          status: 500,
          headers: {
            "Cache-Control": "no-store",
            Pragma: "no-cache",
          },
        },
      );
    }
  }
}
