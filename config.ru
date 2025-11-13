# Minimal OIDC + Authorization Code flow + client authentication (single-file, no gems)
#
# STATIC_PASSWORD= REDIRECT_URIS=http://localhost:4180/oauth2/callback OIDC_HOST=localhost OIDC_PORT=9292 bundle exec rackup config.ru -p 9292 -o 0.0.0.0
#
# Endpoints:
#   GET  /.well-known/openid-configuration
#   GET  /jwks.json
#   GET  /authorize        (shows login/consent form)
#   POST /authorize        (handles login -> redirect with code)
#   POST /token            (grant_type=password OR grant_type=authorization_code)
#   GET  /userinfo         (Authorization: Bearer <access_token>)
#
# Demo client (in CLIENTS hash):
#   client_id: minimal-client
#   client_secret: secret123
#   redirect_uri: http://oauth2-proxy:4180/oauth2/callback
#
require 'rack'
require 'json'
require 'openssl'
require 'base64'
require 'securerandom'
require 'time'
require 'erb'

module MinimalOIDC
  class Server
    # --- Mocked user ---
    USER = {
      'sub' => 'user-123',
      'preferred_username' => 'alice',
      'email' => 'alice@example.com',
      'name' => 'Alice Mock'
    }
    STATIC_PASSWORD = ENV.fetch('STATIC_PASSWORD')

    # --- In-memory clients (client auth) ---
    # Add other clients here for testing. redirect_uris is an array.
    CLIENTS = {
      'minimal-client' => {
        secret: 'secret123',
        redirect_uris: [ENV.fetch('REDIRECT_URIS')] #TODO: map this to EKS staging/okta
      }
    }

    def initialize
      @rsa = OpenSSL::PKey::RSA.generate(2048)
      @kid = SecureRandom.hex(8)

      # stores: auth_code => { client_id, redirect_uri, sub, exp }
      @auth_codes = {}

      # store tokens mapping (access_token => claims)
      @issued_access_tokens = {}
    end

    def call(env)
      req = Rack::Request.new(env)
      base = issuer_from_request(req)

      case [req.request_method, req.path_info]
      when ['GET', '/.well-known/openid-configuration']
        respond_json(openid_configuration(base))
      when ['GET', '/jwks.json']
        respond_json(jwks_response)
      when ['GET', '/authorize']
        show_authorize_form(req)
      when ['POST', '/authorize']
        handle_authorize_post(req)
      when ['POST', '/token']
        handle_token(req)
      when ['GET', '/userinfo']
        handle_userinfo(req)
      else
        respond_404
      end
    end

    private

    def issuer_from_request(req)
      scheme = req.scheme
      host = ENV['OIDC_HOST'] || req.host
      port = ENV['OIDC_PORT'] || req.port
      default_port = (scheme == 'https' ? 443 : 80)
      if port == default_port
        "#{scheme}://#{host}"
      else
        "#{scheme}://#{host}:#{port}"
      end
    end

    def openid_configuration(base)
      {
        issuer: base,
        authorization_endpoint: "#{base}/authorize",
        token_endpoint: "#{base}/token",
        userinfo_endpoint: "#{base}/userinfo",
        jwks_uri: "#{base}/jwks.json",
        response_types_supported: ['code', 'id_token', 'token'],
        grant_types_supported: ['authorization_code', 'password'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256']
      }
    end

    def jwks_response
      pub = @rsa.public_key
      n = base64url(pub.n.to_s(2))
      e = base64url(pub.e.to_s(2))
      {
        keys: [
          {
            kty: 'RSA',
            use: 'sig',
            kid: @kid,
            alg: 'RS256',
            n: n,
            e: e
          }
        ]
      }
    end

    # ----------------- /authorize -----------------
    # GET: render a minimal login/consent form
    def show_authorize_form(req)
      # required params per OIDC: response_type=code, client_id, redirect_uri (recommended), state optional
      response_type = req.params['response_type']
      client_id = req.params['client_id']
      redirect_uri = req.params['redirect_uri']
      state = req.params['state']

      unless response_type == 'code' && valid_client_and_redirect?(client_id, redirect_uri)
        return respond_plain(400, "Invalid request: ensure response_type=code, client_id and redirect_uri are valid.")
      end

      html = <<~HTML
        <!doctype html>
        <html>
        <head><meta charset="utf-8"><title>Login - Minimal OIDC</title></head>
        <body>
          <h1>Sign in to authorize #{ERB::Util.html_escape(client_id)}</h1>
          <form method="post" action="/authorize">
            <input type="hidden" name="response_type" value="#{h response_type}">
            <input type="hidden" name="client_id" value="#{h client_id}">
            <input type="hidden" name="redirect_uri" value="#{h redirect_uri}">
            <input type="hidden" name="state" value="#{h state}">
            <label>Username: <input name="username" value="alice"></label><br>
            <label>Password: <input type="password" name="password"></label><br>
            <button type="submit">Sign in and authorize</button>
          </form>
          <p>Demo user: <strong>alice</strong> / <strong>password123</strong></p>
        </body>
        </html>
      HTML

      [200, { 'content-type' => 'text/html', 'content-length' => html.bytesize.to_s }, [html]]
    end

    # POST /authorize: validate credentials and redirect with code
    def handle_authorize_post(req)
      params = req.POST rescue {}
      response_type = params['response_type']
      client_id = params['client_id']
      redirect_uri = params['redirect_uri']
      state = params['state']
      username = params['username']
      password = params['password']

      unless response_type == 'code' && valid_client_and_redirect?(client_id, redirect_uri)
        return respond_plain(400, "Invalid authorize request")
      end

      unless username == USER['preferred_username'] && password == STATIC_PASSWORD
        # show simple failure page with a link back to form
        html = <<~HTML
          <!doctype html>
          <html><body>
            <h1>Login failed</h1>
            <p>Invalid username or password.</p>
            <a href="/authorize?response_type=code&client_id=#{h client_id}&redirect_uri=#{h redirect_uri}&state=#{h state}">Try again</a>
          </body></html>
        HTML
        return [401, { 'content-type' => 'text/html' }, [html]]
      end

      # create auth code
      code = SecureRandom.hex(16)
      @auth_codes[code] = {
        client_id: client_id,
        redirect_uri: redirect_uri,
        sub: USER['sub'],
        created_at: Time.now.to_i,
        exp: (Time.now.to_i + 300) # 5 minutes
      }

      # redirect back to client
      uri = URI.parse(redirect_uri)
      q = URI.decode_www_form(String(uri.query || '')) rescue []
      q << ['code', code]
      q << ['state', state] if state && state != ''
      uri.query = URI.encode_www_form(q)
      [302, { 'location' => uri.to_s }, []]
    end

    def valid_client_and_redirect?(client_id, redirect_uri)
      return false unless client_id && redirect_uri
      client = CLIENTS[client_id]
      return false unless client
      # require exact match against one of allowed redirect URIs
      client[:redirect_uris].include?(redirect_uri)
    end

    # ----------------- /token -----------------
    # supports grant_type=password (existing) and grant_type=authorization_code (new)
    def handle_token(req)
      params = req.POST rescue {}
      grant = params['grant_type'] || params['grantType']

      case grant
      when 'password'
        handle_token_password(req, params)
      when 'authorization_code'
        handle_token_authorization_code(req, params)
      else
        respond_json({ error: 'unsupported_grant_type', error_description: 'Only password and authorization_code are supported.' }, 400)
      end
    end

    def handle_token_password(req, params)
      username = params['username']
      password = params['password']
      client_id = params['client_id'] # optional for password flow in our minimal impl

      unless username == USER['preferred_username'] && password == STATIC_PASSWORD
        return respond_json({ error: 'invalid_grant', error_description: 'Invalid username or password' }, 400)
      end

      now = Time.now.to_i
      exp = now + 3600

      access_claims = {
        iss: issuer_from_env(req.env),
        sub: USER['sub'],
        aud: client_id || 'minimal-client',
        iat: now,
        exp: exp,
        scope: 'openid profile email'
      }
      access_token = sign_jwt(access_claims)

      id_claims = {
        iss: issuer_from_env(req.env),
        sub: USER['sub'],
        aud: client_id || 'minimal-client',
        iat: now,
        exp: exp,
        name: USER['name'],
        preferred_username: USER['preferred_username'],
        email: USER['email']
      }
      id_token = sign_jwt(id_claims)

      @issued_access_tokens[access_token] = access_claims.merge(user_claims: USER)

      body = {
        access_token: access_token,
        token_type: 'Bearer',
        expires_in: (exp - now),
        id_token: id_token,
        scope: 'openid profile email'
      }
      respond_json(body)
    end

    def handle_token_authorization_code(req, params)
      # client authentication (HTTP Basic preferred)
      client_id, client_secret = extract_client_credentials(req, params)
      unless client_id && client_secret
        return respond_json({ error: 'invalid_client', error_description: 'Client authentication required' }, 401)
      end

      client = CLIENTS[client_id]
      unless client && client[:secret] == client_secret
        return respond_json({ error: 'invalid_client', error_description: 'Unknown client or bad secret' }, 401)
      end

      code = params['code']
      redirect_uri = params['redirect_uri']

      stored = @auth_codes.delete(code) # single-use: delete on fetch
      unless stored
        return respond_json({ error: 'invalid_grant', error_description: 'Invalid or already-used code' }, 400)
      end

      # validate client_id and redirect_uri match what was used for authorization
      if stored[:client_id] != client_id
        return respond_json({ error: 'invalid_grant', error_description: 'Code was not issued to this client' }, 400)
      end
      if stored[:redirect_uri] != redirect_uri
        return respond_json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' }, 400)
      end

      if Time.now.to_i > stored[:exp].to_i
        return respond_json({ error: 'invalid_grant', error_description: 'Code expired' }, 400)
      end

      # success: issue tokens
      now = Time.now.to_i
      exp = now + 3600

      access_claims = {
        iss: issuer_from_env(req.env),
        sub: stored[:sub],
        aud: client_id,
        iat: now,
        exp: exp,
        scope: 'openid profile email'
      }
      access_token = sign_jwt(access_claims)

      id_claims = {
        iss: issuer_from_env(req.env),
        sub: stored[:sub],
        aud: client_id,
        iat: now,
        exp: exp,
        name: USER['name'],
        preferred_username: USER['preferred_username'],
        email: USER['email']
      }
      id_token = sign_jwt(id_claims)

      @issued_access_tokens[access_token] = access_claims.merge(user_claims: USER)

      body = {
        access_token: access_token,
        token_type: 'Bearer',
        expires_in: (exp - now),
        id_token: id_token,
        scope: 'openid profile email'
      }
      respond_json(body)
    end

    # extract client credentials from Authorization Basic header or POST body
    def extract_client_credentials(req, params)
      auth = req.get_header('HTTP_AUTHORIZATION') || ''
      if auth =~ /^Basic\s+(.+)$/i
        decoded = Base64.decode64($1 || '')
        client_id, client_secret = decoded.split(':', 2)
        return [client_id, client_secret]
      end
      [params['client_id'], params['client_secret']]
    end

    # ----------------- /userinfo -----------------
    def handle_userinfo(req)
      auth = req.get_header('HTTP_AUTHORIZATION') || ''
      unless auth =~ /^Bearer\s+(.+)$/
        return respond_json({ error: 'invalid_request', error_description: 'Missing Authorization Bearer token' }, 401)
      end
      token = $1

      begin
        payload = verify_jwt(token)
      rescue => e
        return respond_json({ error: 'invalid_token', error_description: "Token invalid: #{e.message}" }, 401)
      end

      claims = {
        sub: payload['sub'],
        name: payload['name'] || USER['name'],
        preferred_username: payload['preferred_username'] || USER['preferred_username'],
        email: payload['email'] || USER['email'],
        groups: ['users', 'admins'] # static groups for demo
      }
      respond_json(claims)
    end

    # ----- helpers -----
    def respond_json(obj, status=200)
      body = JSON.generate(obj)
      [status, { 'content-type' => 'application/json', 'content-length' => body.bytesize.to_s }, [body]]
    end

    def respond_plain(status, text)
      [status, { 'content-type' => 'text/plain', 'content-length' => text.bytesize.to_s }, [text]]
    end

    def respond_404
      [404, { 'content-type' => 'text/plain' }, ['Not Found']]
    end

    # ----- JWT helpers (RS256) -----
    def sign_jwt(payload, header_add = {})
      header = { alg: 'RS256', typ: 'JWT', kid: @kid }.merge(header_add)
      segments = []
      segments << base64url(header.to_json)
      segments << base64url(payload.to_json)
      signing_input = segments.join('.')
      signature = @rsa.sign(OpenSSL::Digest::SHA256.new, signing_input)
      segments << base64url(signature)
      segments.join('.')
    end

    def verify_jwt(token)
      parts = token.split('.')
      raise "malformed token" unless parts.length == 3
      header_b, payload_b, sig_b = parts
      header = JSON.parse(base64url_decode_to_s(header_b))
      payload = JSON.parse(base64url_decode_to_s(payload_b))
      signature = base64url_decode(sig_b)

      raise "unexpected alg #{header['alg']}" unless header['alg'] == 'RS256'
      unless @rsa.public_key.verify(OpenSSL::Digest::SHA256.new, signature, "#{header_b}.#{payload_b}")
        raise "signature verification failed"
      end
      if payload['exp'] && Time.now.to_i > payload['exp'].to_i
        raise "token expired"
      end
      payload
    end

    # base64url helpers
    def base64url(bin_or_str)
      s = bin_or_str.is_a?(String) ? bin_or_str : bin_or_str.to_s
      Base64.urlsafe_encode64(s, padding: false)
    end

    def base64url_decode(segment)
      padded = segment + '=' * ((4 - segment.length % 4) % 4)
      Base64.urlsafe_decode64(padded)
    end

    def base64url_decode_to_s(segment)
      base64url_decode(segment).force_encoding('utf-8')
    end

    def issuer_from_env(env)
      scheme = env['rack.url_scheme'] || 'http'
      host = ENV['OIDC_HOST'] || env['HTTP_HOST'] || env['SERVER_NAME']
      "#{scheme}://#{host}"
    end

    # small helper for escaping in HTML
    def h(s)
      ERB::Util.html_escape(s.to_s)
    end
  end
end

run MinimalOIDC::Server.new
