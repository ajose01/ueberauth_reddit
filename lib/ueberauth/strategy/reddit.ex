defmodule Ueberauth.Strategy.Reddit do
  use Ueberauth.Strategy, default_scope: "identity,history,read",
  uid_field: :id

  alias Ueberauth.Auth.Info
  alias Ueberauth.Auth.Credentials
  alias Ueberauth.Auth.Extra
  alias Ueberauth.Strategy.Reddit

  @doc """
  Handles initial request for Reddit authentication"
  """
  def handle_request!(conn) do
    # Pending
  end

  def handle_callback!(%Plug.Conn{params: %{"code" => code}} = conn) do
    client = Reddit.OAuth.get_token!([code: code])
    token = client.token

    if token.access_token == nil do
      set_errors!(conn, [error(token.other_params["error"], token.other_params["error_description"])])
    else
      fetch_user(conn, token)
    end

  end

  @doc false
  def handle_callback!(conn) do
    set_errors!(conn, [error("missing_code", "No code received")])
  end

  @doc """
  Cleans up the private area of the connection used for passing the raw Reddit response around during the callback.
  """
  def handle_cleanup!(conn) do
    conn
    |> put_private(:reddit_user, nil)
    |> put_private(:reddit_token, nil)
  end

  @doc """
  Fetches the uid field from the Reddit response. This defaults to the option `uid_field` which in-turn defaults to `id`
  """
  def uid(conn) do
    user =
      conn
      |> option(:uid_field)
      |> to_string
    conn.private.reddit_user[user]
  end

  @doc """
  Includes the credentials from the Reddit response.
  """
  def credentials(conn) do
    token        = conn.private.reddit_token
    scope_string = (token.other_params["scope"] || "")
    scopes       = String.split(scope_string, ",")

    %Credentials{
      token: token.access_token,
      refresh_token: token.refresh_token,
      expires_at: token.expires_at,
      token_type: token.token_type,
      expires: !!token.expires_at,
      scopes: scopes
    }
  end

  @doc """
  Fetches the fields to populate the info section of the `Ueberauth.Auth` struct.
  """

  def info(conn) do
    user = conn.private.reddit_user

    %Info{
      name: user["name"]
    }
  end

  @doc """
  Stores the raw information (including the token) obtained from the Github callback.
  
  Total keys available in raw_info.user:
  pry(2)> Map.keys user
  ["comment_karma", "created", "created_utc", "features", "gold_creddits",
   "gold_expiration", "has_subscribed", "has_verified_email", "hide_from_robots",
   "id", "in_beta", "inbox_count", "is_employee", "is_gold", "is_mod",
   "is_sponsor", "is_suspended", "link_karma", "name", "oauth_client_id",
   "over_18", "pref_geopopular", "pref_no_profanity", "pref_show_snoovatar",
   "pref_top_karma_subreddits", "subreddit", "suspension_expiration_utc",
   "verified"]
  """
  def extra(conn) do
    %Extra {
      raw_info: %{
        token: conn.private.reddit_token,
        user: conn.private.reddit_user
      }
    }
  end

  defp fetch_user(conn, token) do
    conn = put_private(conn, :reddit_token, token)
    case Reddit.OAuth.get(token, "/api/v1/me") do
      {:ok, %OAuth2.Response{status_code: 200, body: user}} ->
        put_private(conn, :reddit_user, user)
      {:ok, %OAuth2.Response{status_code: 401}} ->
        set_errors!(conn, [error("token", "unauthorized")])
      {:error, %OAuth2.Error{reason: reason}} ->
        set_errors!(conn, [error("OAuth2", reason)])
    end
  end

  defp option(conn, key) do
    Keyword.get(options(conn), key, Keyword.get(default_options(), key))
  end
end
