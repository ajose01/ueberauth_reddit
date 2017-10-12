defmodule Ueberauth.Strategy.Reddit.OAuth do
  use OAuth2.Strategy

  @defaults [
    strategy: __MODULE__,
    site: "https://oauth.reddit.com",
    token_url: "https://www.reddit.com/api/v1/access_token",
    redirect_uri: System.get_env("REDDIT_REDIRECT_URI"),
    authorize_url: "https://oauth.reddit.com"
  ]

  def client(opts \\ []) do
    config = Application.get_env(:ueberauth, __MODULE__)
    IO.inspect config

    opts =
      @defaults
      |> Keyword.merge(config)
      |> Keyword.merge(opts)

    OAuth2.Client.new(opts)
  end

  @doc """
  Provides the authorize url for the request phase of Ueberauth.
  No need to call this usually.
  """
  def authorize_url!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.authorize_url!(params)
  end

  def get(token, url) do
    [token: token]
    |> client
    |> OAuth2.Client.get(url, [], [])
  end

  def get_token!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Client.get_token!(params)
  end

  def refresh_token!(params \\ [], opts \\ []) do
    opts
    |> client
    |> OAuth2.Strategy.Refresh.get_token([refresh_token: Keyword.get(params, :refresh_token)], opts)
    |> OAuth2.Client.refresh_token!(params)
  end

  # Strategy Callbacks

  def authorize_url(client, params) do
    OAuth2.Strategy.AuthCode.authorize_url(client, params)
  end

  def get_token(client, params, headers) do
    client
    |> put_param(:grant_type, "authorization_code")
    |> put_param(:code, Keyword.get(params, :code))
    |> basic_auth
    |> put_header("duration", "permanent")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end

  def refresh_token(client, params, headers \\ [], opts \\ []) do
    client
    |> put_param(:grant_type, "refresh_token")
    |> put_param(:refresh_token, Keyword.get(params, :refresh_token))
    |> basic_auth
    |> put_header(:duration, "permanent")
    |> OAuth2.Strategy.AuthCode.get_token(params, headers)
  end
end
