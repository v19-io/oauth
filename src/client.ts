interface ClientConfig {
  storeValue: (key: string, value: string) => Promise<void>;
  getValue: (key: string) => Promise<string>;
  removeValue: (key: string) => Promise<void>;
  redirect: (url: URL) => void;
}

type Flow =
  | AuthorizationCodeFlow
  | ImplicitFlow
  | PasswordFlow
  | ClientCredentialsFlow;

interface BaseConfig {
  clientId: string;
  redirectUri: URL;
  tokenUrl: URL;
}

interface AuthorizationCodeFlow extends BaseConfig {
  grantType: "authorization_code";
  authorizationUrl: URL;
}

interface ServerSideAuthorizationCodeFlow extends AuthorizationCodeFlow {
  clientSecret: string;
}

interface ImplicitFlow extends BaseConfig {
  grantType: "implicit";
  authorizationUrl: URL;
}

interface PasswordFlow extends BaseConfig {
  grantType: "password";
  clientSecret: string;
  username: string;
  password: string;
}

interface ClientCredentialsFlow extends BaseConfig {
  grantType: "client_credentials";
  clientSecret: string;
}

interface RefreshTokenFlow extends BaseConfig {
  grantType: "refresh_token";
  clientSecret: string;
}

interface RevocationFlow {
  clientId: string;
  clientSecret: string;
  revocationUrl: URL;
}

type AuthenticationResult = {
  accessToken: string;
  refreshToken?: string;
  expiresIn?: number;
  scopes?: string[];
};

class Client {
  constructor(private config: ClientConfig) {}

  async authorize(
    provider: AuthorizationCodeFlow | ImplicitFlow,
  ): Promise<never>;
  async authorize(
    provider: PasswordFlow | ClientCredentialsFlow,
  ): Promise<AuthenticationResult>;
  async authorize(provider: Flow) {
    if (
      provider.grantType === "authorization_code" ||
      provider.grantType === "implicit"
    ) {
      const state = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map((v) => v.toString(16).padStart(2, "0"))
        .join("");
      await this.config.storeValue("state", state);
      const url = new URL(provider.authorizationUrl.toString());
      url.searchParams.append("client_id", provider.clientId);
      url.searchParams.append("redirect_uri", provider.redirectUri.toString());
      url.searchParams.append(
        "response_type",
        provider.grantType === "authorization_code" ? "code" : "token",
      );
      url.searchParams.append("state", state);
      this.config.redirect(url);
    } else if (
      provider.grantType === "password" ||
      provider.grantType === "client_credentials"
    ) {
      const url = new URL(provider.tokenUrl.toString());
      const body = new URLSearchParams();
      body.append("grant_type", provider.grantType);
      body.append("client_id", provider.clientId);
      body.append("client_secret", provider.clientSecret);
      if (provider.grantType === "password") {
        body.append("username", provider.username);
        body.append("password", provider.password);
      }
      const response = await fetch(url.toString(), {
        method: "POST",
        body: body.toString(),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });
      const json: {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
        scope?: string;
        error?: string;
        error_description?: string;
      } = (await response.json()) as any;
      if (json.error) {
        throw new Error(`OAuth Error: ${json.error} ${json.error_description}`);
      }
      return {
        accessToken: json.access_token,
        refreshToken: json.refresh_token,
        expiresIn: json.expires_in,
        scopes: json.scope?.split(" "),
      } as AuthenticationResult;
    } else {
      throw new Error("Invalid grant type");
    }
  }

  async callback(
    provider: ServerSideAuthorizationCodeFlow | ImplicitFlow,
    url: URL,
  ): Promise<AuthenticationResult> {
    if (provider.grantType === "implicit") {
      const accessToken = url.searchParams.get("access_token");
      const expiresIn = url.searchParams.get("expires_in");
      const scope = url.searchParams.get("scope");
      const state = url.searchParams.get("state");
      const expectedState = await this.config.getValue("state");
      await this.config.removeValue("state");
      if (state !== expectedState) {
        throw new Error("Invalid state");
      }
      if (!accessToken) {
        throw new Error("No access token");
      }
      return {
        accessToken: accessToken,
        refreshToken: "",
        expiresIn: expiresIn ? parseInt(expiresIn) : undefined,
        scopes: scope?.split(" "),
      };
    } else if (provider.grantType === "authorization_code") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      const expectedState = await this.config.getValue("state");
      await this.config.removeValue("state");
      if (state !== expectedState) {
        throw new Error("Invalid state");
      }
      if (!code) {
        throw new Error("No code");
      }
      const body = new URLSearchParams();
      body.append("grant_type", "authorization_code");
      body.append("client_id", provider.clientId);
      body.append("client_secret", provider.clientSecret);
      body.append("code", code);
      body.append("redirect_uri", provider.redirectUri.toString());
      const response = await fetch(provider.tokenUrl.toString(), {
        method: "POST",
        body: body.toString(),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });
      const json: {
        access_token: string;
        refresh_token?: string;
        expires_in?: number;
        scope?: string;
        error?: string;
        error_description?: string;
      } = (await response.json()) as any;
      if (json.error) {
        throw new Error(`OAuth Error: ${json.error} ${json.error_description}`);
      }
      return {
        accessToken: json.access_token,
        refreshToken: json.refresh_token,
        expiresIn: json.expires_in,
        scopes: json.scope?.split(" "),
      };
    }
    throw new Error("Invalid grant type");
  }

  async refresh(
    provider: RefreshTokenFlow,
    refreshToken: string,
    scopes?: string[],
  ): Promise<AuthenticationResult> {
    const url = new URL(provider.tokenUrl.toString());
    const body = new URLSearchParams();
    body.append("grant_type", "refresh_token");
    body.append("client_id", provider.clientId);
    body.append("client_secret", provider.clientSecret);
    body.append("refresh_token", refreshToken);
    if (scopes) {
      body.append("scope", scopes.join(" "));
    }
    const response = await fetch(url.toString(), {
      method: "POST",
      body: body.toString(),
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    });
    const json: {
      access_token: string;
      refresh_token?: string;
      expires_in?: number;
      scope?: string;
      error?: string;
      error_description?: string;
    } = (await response.json()) as any;
    if (json.error) {
      throw new Error(`OAuth Error: ${json.error} ${json.error_description}`);
    }
    return {
      accessToken: json.access_token,
      refreshToken: json.refresh_token,
      expiresIn: json.expires_in,
      scopes: json.scope?.split(" "),
    };
  }

  async revoke(
    provider: RevocationFlow,
    token: string,
    hint?: "access_token" | "refresh_token",
  ): Promise<void> {
    const url = new URL(provider.revocationUrl.toString());
    const body = new URLSearchParams();
    body.append("token", token);
    body.append("client_id", provider.clientId);
    body.append("client_secret", provider.clientSecret);
    if (hint) {
      body.append("token_type_hint", hint);
    }
    const response = await fetch(url.toString(), {
      method: "POST",
      body: body.toString(),
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${btoa(
          `${provider.clientId}:${provider.clientSecret}`,
        )}`,
      },
    });
    if (!response.ok) {
      throw new Error(`Failed to revoke token: ${response.statusText}`);
    }
  }
}
