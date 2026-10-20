require 'rack'
require 'json'
require 'openssl'
require 'base64'
require 'securerandom'
require 'time'
require 'erb'
require 'uri'
require 'zlib'
require 'onelogin/ruby-saml'

module MinimalSAML
  class Server
    PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol'
    ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion'
    METADATA = 'urn:oasis:names:tc:SAML:2.0:metadata'
    POST_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
    REDIRECT_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
    NAME_ID_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
    AUTHN_CONTEXT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
    MAX_XML = 65_536
    MAX_INPUT = 131_072
    TTL = 300
    NS = { 'samlp' => PROTOCOL, 'saml' => ASSERTION }
    class InvalidRequest < StandardError; end
    class ProfileNotFound < StandardError; end

    def initialize(user:, password:)
      @user, @password = user, password
      @profiles, @pending = {}, {}
      @mutex = Mutex.new
    end

    def call(env)
      req = Rack::Request.new(env)
      host = req.host.downcase
      if ['/crud/saml', '/saml/consume'].include?(req.path_info)
        return reply(404, 'Not Found') unless ENV['SAML_DEBUG'] == 'true'
        return unauthorized unless debug_authorized?(env)
      end

      case [req.request_method, req.path_info]
      when ['GET', '/crud/saml']
        json(public_profile(find_profile(host)))
      when ['POST', '/crud/saml']
        check_origin(req)
        configure(req, host)
      when ['DELETE', '/crud/saml']
        check_origin(req)
        delete_profile(host)
      when ['GET', '/saml/metadata']
        reply(200, metadata(find_profile(host)), 'application/samlmetadata+xml')
      when ['GET', '/saml/certificate']
        reply(200, find_profile(host)[:certificate].to_pem, 'application/x-pem-file')
      when ['GET', '/saml/sso'], ['POST', '/saml/sso']
        sso(req, find_profile(host), parameters(req))
      when ['GET', '/saml/consume'], ['POST', '/saml/consume']
        consume(find_profile(host), parameters(req))
      else
        reply(404, 'Not Found')
      end
    rescue ProfileNotFound => e
      json({ error: e.message }, 404)
    rescue InvalidRequest, JSON::ParserError, Rack::QueryParser::ParameterTypeError,
           Rack::QueryParser::InvalidParameterError, Rack::QueryParser::ParamsTooDeepError => e
      json({ error: e.message }, 400)
    end

    private

    def reply(status, body, type = 'text/plain', headers = {})
      headers = {
        'content-type' => "#{type}; charset=utf-8",
        'content-length' => body.bytesize.to_s,
        'cache-control' => 'no-store',
        'x-content-type-options' => 'nosniff',
        'referrer-policy' => 'no-referrer',
        'content-security-policy' => "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
      }.merge(headers)
      if status == 204
        headers.delete('content-type')
        headers.delete('content-length')
      end
      [status, headers, body.empty? ? [] : [body]]
    end

    def json(value, status = 200)
      reply(status, JSON.generate(value), 'application/json')
    end

    def unauthorized
      reply(401, 'Debug access requires alice and a nonempty STATIC_PASSWORD.',
            'text/plain', 'www-authenticate' => 'Basic realm="SAML debug"')
    end

    def valid_credentials?(username, password)
      username == @user['preferred_username'] && password.is_a?(String) &&
        !@password.empty? && Rack::Utils.secure_compare(@password, password)
    end

    def debug_authorized?(env)
      auth = Rack::Auth::Basic::Request.new(env)
      return false unless auth.provided? && auth.basic?
      username, password = auth.credentials
      valid_credentials?(username, password)
    end

    def check_origin(req)
      origin = req.get_header('HTTP_ORIGIN')
      if (origin && origin != req.base_url) || req.get_header('HTTP_SEC_FETCH_SITE') == 'cross-site'
        raise InvalidRequest, 'Cross-origin configuration changes are not allowed'
      end
    end

    def parameters(req)
      raise InvalidRequest, 'Request too large' if req.query_string.bytesize > MAX_INPUT
      if req.post?
        body = req.body&.read(MAX_INPUT + 1) || ''
        req.body&.rewind
        raise InvalidRequest, 'Request too large' if body.bytesize > MAX_INPUT
        if req.media_type == 'application/json'
          value = JSON.parse(body)
          raise InvalidRequest, 'Expected a JSON object' unless value.is_a?(Hash)
          return value
        end
      end
      req.params
    end

    def text(value, label, limit = 2048)
      unless value.is_a?(String) && !value.empty? && value.bytesize <= limit &&
             value.valid_encoding? && !value.match?(/[[:cntrl:]]/)
        raise InvalidRequest, "Invalid #{label}"
      end
      value
    end

    def http_url(value, label)
      uri = URI.parse(text(value, label))
      unless ['http', 'https'].include?(uri.scheme) && uri.host && !uri.userinfo && !uri.fragment
        raise InvalidRequest, "Invalid #{label}: use an absolute HTTP(S) URL without credentials or fragment"
      end
      uri
    rescue URI::InvalidURIError
      raise InvalidRequest, "Invalid #{label}"
    end

    def find_profile(host)
      @mutex.synchronize { @profiles[host] } || raise(ProfileNotFound, 'No SAML profile for this hostname; POST /crud/saml first')
    end

    def configure(req, host)
      params = parameters(req)
      return delete_profile(host) if params == { 'action' => 'delete' }
      allowed = %w[sp_entity_id acs_url idp_base_url name_id attributes]
      raise InvalidRequest, 'Unknown profile fields' unless (params.keys - allowed).empty?

      @mutex.synchronize do
        old = @profiles[host]
        raise InvalidRequest, 'Profile limit reached' if !old && @profiles.size >= 100
        base = params.fetch('idp_base_url', old ? old[:base] : req.base_url)
        uri = http_url(base, 'idp_base_url')
        unless uri.host.downcase == host && ['', '/'].include?(uri.path) && !uri.query
          raise InvalidRequest, 'idp_base_url must be an origin for the current hostname'
        end
        base = base.delete_suffix('/')
        profile = {
          host: host, base: base,
          sp_entity_id: params.fetch('sp_entity_id', old && old[:sp_entity_id]),
          acs_url: params.fetch('acs_url', old ? old[:acs_url] : "#{base}/saml/consume"),
          name_id: params.fetch('name_id', old ? old[:name_id] : @user['email']),
          attributes: params.fetch('attributes', old ? old[:attributes] : @user)
        }
        text(profile[:sp_entity_id], 'sp_entity_id')
        http_url(profile[:acs_url], 'acs_url')
        text(profile[:name_id], 'name_id')
        attributes = profile[:attributes]
        unless attributes.is_a?(Hash) && attributes.size <= 50
          raise InvalidRequest, 'attributes must be an object with at most 50 entries'
        end
        attributes.each do |name, values|
          text(name, 'attribute name', 256)
          values = [values] unless values.is_a?(Array)
          raise InvalidRequest, 'Too many attribute values' if values.size > 50
          values.each { |value| text(value, 'attribute value') }
        end
        key, certificate = old ? old.values_at(:key, :certificate) : signing_material(host)
        profile.merge!(key: key, certificate: certificate)
        @profiles[host] = profile
        json(public_profile(profile), old ? 200 : 201)
      end
    end

    def delete_profile(host)
      removed = @mutex.synchronize { @profiles.delete(host) }
      removed ? reply(204, '') : reply(404, 'Not Found')
    end

    def signing_material(host)
      key = OpenSSL::PKey::RSA.generate(2048)
      cert = OpenSSL::X509::Certificate.new
      cert.version = 2
      cert.serial = SecureRandom.random_number(2**128)
      cert.subject = OpenSSL::X509::Name.new([['CN', host.byteslice(0, 64)]])
      cert.issuer = cert.subject
      cert.public_key = key.public_key
      cert.not_before = Time.now - 60
      cert.not_after = Time.now + 365 * 24 * 60 * 60
      factory = OpenSSL::X509::ExtensionFactory.new
      factory.subject_certificate = factory.issuer_certificate = cert
      cert.add_extension(factory.create_extension('basicConstraints', 'CA:FALSE', true))
      cert.add_extension(factory.create_extension('keyUsage', 'digitalSignature', true))
      cert.sign(key, OpenSSL::Digest::SHA256.new)
      [key, cert]
    end

    def public_profile(profile)
      {
        hostname: profile[:host],
        idp_sso_url: "#{profile[:base]}/saml/sso",
        idp_entity_id: "#{profile[:base]}/saml/metadata",
        metadata_url: "#{profile[:base]}/saml/metadata",
        certificate_url: "#{profile[:base]}/saml/certificate",
        x509_certificate: profile[:certificate].to_pem,
        consumer_url: "#{profile[:base]}/saml/consume",
        sp_entity_id: profile[:sp_entity_id],
        acs_url: profile[:acs_url],
        name_id: profile[:name_id],
        name_id_format: NAME_ID_FORMAT,
        attributes: profile[:attributes]
      }
    end

    def metadata(profile)
      config = public_profile(profile)
      Nokogiri::XML::Builder.new do |xml|
        xml.EntityDescriptor('xmlns' => METADATA, 'xmlns:ds' => XMLSecurity::Document::DSIG,
                             'entityID' => config[:idp_entity_id]) do
          xml.IDPSSODescriptor('protocolSupportEnumeration' => PROTOCOL, 'WantAuthnRequestsSigned' => 'false') do
            xml.KeyDescriptor('use' => 'signing') do
              xml['ds'].KeyInfo do
                xml['ds'].X509Data { xml['ds'].X509Certificate Base64.strict_encode64(profile[:certificate].to_der) }
              end
            end
            xml.NameIDFormat NAME_ID_FORMAT
            [REDIRECT_BINDING, POST_BINDING].each do |binding|
              xml.SingleSignOnService('Binding' => binding, 'Location' => config[:idp_sso_url])
            end
          end
        end
      end.to_xml
    end

    def decode_message(value, redirect: false)
      text(value, 'SAML message', MAX_INPUT)
      decoded = Base64.strict_decode64(value)
      if redirect
        inflater = Zlib::Inflate.new(-Zlib::MAX_WBITS)
        begin
          output = +''
          inflater.inflate(decoded) do |chunk|
            raise InvalidRequest, 'SAML XML too large' if output.bytesize + chunk.bytesize > MAX_XML
            output << chunk
          end
          raise InvalidRequest, 'Incomplete deflated SAML message' unless inflater.finished?
          decoded = output
        ensure
          inflater.close
        end
      end
      raise InvalidRequest, 'SAML XML too large' if decoded.bytesize > MAX_XML
      doc = Nokogiri::XML(decoded) { |config| config.strict.nonet }
      raise InvalidRequest, 'SAML XML must not contain a DTD' if doc.internal_subset
      doc
    rescue ArgumentError, Zlib::Error, Nokogiri::XML::SyntaxError
      raise InvalidRequest, 'Malformed SAML message'
    end

    def authn_request(value, profile, redirect:)
      doc = decode_message(value, redirect: redirect)
      root = doc.root
      unless root && root.name == 'AuthnRequest' && root.namespace&.href == PROTOCOL &&
             root['Version'] == '2.0' && root['ID']&.match?(/\A[A-Za-z_][A-Za-z0-9_.-]{0,255}\z/)
        raise InvalidRequest, 'Expected a SAML 2.0 AuthnRequest with an ID'
      end
      issuers = root.xpath('./saml:Issuer', NS)
      raise InvalidRequest, 'Unknown SP issuer' unless issuers.size == 1 && issuers.first.text == profile[:sp_entity_id]
      expected = { 'Destination' => "#{profile[:base]}/saml/sso",
                   'AssertionConsumerServiceURL' => profile[:acs_url], 'ProtocolBinding' => POST_BINDING }
      expected.each do |field, value|
        raise InvalidRequest, "Unexpected #{field}" if root[field] && root[field] != value
      end
      if root['AssertionConsumerServiceIndex'] || ['true', '1'].include?(root['IsPassive']) ||
         root.at_xpath('./samlp:Scoping', NS)
        raise InvalidRequest, 'Indexed ACS, passive login and scoping are not supported'
      end
      context = root.at_xpath('./samlp:RequestedAuthnContext', NS)
      if context
        refs = context.xpath('./saml:AuthnContextClassRef', NS).map(&:text)
        unless ['exact', 'minimum'].include?(context['Comparison'] || 'exact') &&
               refs.include?(authn_context(profile)) && !context.at_xpath('./saml:AuthnContextDeclRef', NS)
          raise InvalidRequest, 'Requested authentication context cannot be satisfied'
        end
      end
      format = root.at_xpath('./samlp:NameIDPolicy', NS)&.[]('Format')
      if format && ![NAME_ID_FORMAT, 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified'].include?(format)
        raise InvalidRequest, 'Only emailAddress NameIDs are supported'
      end
      begin
        issued = Time.iso8601(root['IssueInstant'].to_s)
        raise ArgumentError unless issued.between?(Time.now - TTL, Time.now + 60)
      rescue ArgumentError
        raise InvalidRequest, 'Invalid or expired AuthnRequest IssueInstant'
      end
      [root['ID'], doc.to_xml]
    end

    def sso(req, profile, params)
      if req.post? && params.key?('login_token')
        return complete_login(profile, params)
      end
      request_id, request_xml = authn_request(params['SAMLRequest'], profile, redirect: req.get?) if params.key?('SAMLRequest')
      relay = params['RelayState']
      text(relay, 'RelayState', 2048) if relay && relay != ''
      token = SecureRandom.hex(32)
      @mutex.synchronize do
        @pending.delete_if { |_, pending| pending[:expires] <= Time.now }
        raise InvalidRequest, 'Too many pending logins' if @pending.size >= 1000
        @pending[token] = { profile: profile, request_id: request_id, relay: relay, expires: Time.now + TTL }
      end
      html = <<~HTML
        <!doctype html><html><head><meta charset="utf-8"><title>SAML login</title></head><body>
        <h1>Sign in to #{h profile[:sp_entity_id]}</h1>
        <form method="post" action="/saml/sso">
          <input type="hidden" name="login_token" value="#{h token}">
          <label>Username: <input name="username" value="#{h @user['preferred_username']}"></label>
          <label>Password: <input type="password" name="password"></label>
          <button type="submit">Sign in</button>
        </form>
        <details><summary>Unverified AuthnRequest (debug)</summary><pre>#{h request_xml}</pre></details>
        </body></html>
      HTML
      reply(200, html, 'text/html')
    end

    def complete_login(profile, params)
      token = text(params['login_token'], 'login_token', 64)
      pending = @mutex.synchronize { @pending.delete(token) }
      unless pending && pending[:profile].equal?(profile) && pending[:expires] > Time.now
        raise InvalidRequest, 'Unknown or expired login; start again'
      end
      unless valid_credentials?(params['username'], params['password'])
        return reply(401, 'Invalid credentials; start SAML login again')
      end
      xml = response_xml(profile, pending[:request_id])
      html = <<~HTML
        <!doctype html><html><head><meta charset="utf-8"><title>SAML response</title></head><body>
        <h1>SAML response</h1>
        <form method="post" action="#{h profile[:acs_url]}">
          <input type="hidden" name="SAMLResponse" value="#{Base64.strict_encode64(xml)}">
          #{pending[:relay].nil? ? '' : %(<input type="hidden" name="RelayState" value="#{h pending[:relay]}">)}
          <button type="submit">Continue to service provider</button>
        </form>
        <details><summary>Signed response (debug)</summary><pre>#{h xml}</pre></details>
        </body></html>
      HTML
      reply(200, html, 'text/html')
    end

    def sign(xml, profile)
      doc = XMLSecurity::Document.new(xml)
      doc.sign_document(profile[:key], profile[:certificate],
                        XMLSecurity::Document::RSA_SHA256, XMLSecurity::Document::SHA256)
      doc.to_s
    end

    def response_xml(profile, request_id)
      now = Time.now.utc
      issuer = "#{profile[:base]}/saml/metadata"
      assertion = Nokogiri::XML::Builder.new do |xml|
        # Match the final namespace context before signing the standalone assertion.
        xml['saml'].Assertion('xmlns:saml' => ASSERTION, 'xmlns:samlp' => PROTOCOL, 'ID' => "_#{SecureRandom.hex(20)}",
                              'Version' => '2.0', 'IssueInstant' => now.iso8601) do
          xml['saml'].Issuer issuer
          xml['saml'].Subject do
            xml['saml'].NameID(profile[:name_id], 'Format' => NAME_ID_FORMAT)
            xml['saml'].SubjectConfirmation('Method' => 'urn:oasis:names:tc:SAML:2.0:cm:bearer') do
              attrs = { 'Recipient' => profile[:acs_url], 'NotOnOrAfter' => (now + TTL).iso8601 }
              attrs['InResponseTo'] = request_id if request_id
              xml['saml'].SubjectConfirmationData(attrs)
            end
          end
          xml['saml'].Conditions('NotBefore' => (now - 30).iso8601, 'NotOnOrAfter' => (now + TTL).iso8601) do
            xml['saml'].AudienceRestriction { xml['saml'].Audience profile[:sp_entity_id] }
          end
          xml['saml'].AuthnStatement('AuthnInstant' => now.iso8601, 'SessionIndex' => "_#{SecureRandom.hex(20)}") do
            xml['saml'].AuthnContext { xml['saml'].AuthnContextClassRef authn_context(profile) }
          end
          unless profile[:attributes].empty?
            xml['saml'].AttributeStatement do
              profile[:attributes].each do |name, values|
                xml['saml'].Attribute('Name' => name) do
                  Array(values).each { |value| xml['saml'].AttributeValue value }
                end
              end
            end
          end
        end
      end
      signed_assertion = sign(assertion.doc.root.to_xml(save_with: 0), profile)
      response = Nokogiri::XML::Builder.new do |xml|
        attrs = { 'xmlns:samlp' => PROTOCOL, 'ID' => "_#{SecureRandom.hex(20)}",
                  'Version' => '2.0', 'IssueInstant' => now.iso8601, 'Destination' => profile[:acs_url] }
        attrs['InResponseTo'] = request_id if request_id
        xml['samlp'].Response(attrs) do
          xml['saml'].Issuer(issuer, 'xmlns:saml' => ASSERTION)
          xml['samlp'].Status { xml['samlp'].StatusCode('Value' => 'urn:oasis:names:tc:SAML:2.0:status:Success') }
          xml << signed_assertion
        end
      end
      sign(response.doc.root.to_xml(save_with: 0), profile)
    end

    def authn_context(profile)
      profile[:base].start_with?('https:') ? AUTHN_CONTEXT : 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password'
    end

    def consume(profile, params)
      result = { verified: false, warning: 'Debug inspection only; no signature validation or login is performed.',
                 settings: public_profile(profile) }
      if params.key?('SAMLResponse')
        result[:saml_response_xml] = decode_message(params['SAMLResponse']).to_xml
      end
      if params.key?('RelayState')
        text(params['RelayState'], 'RelayState', 2048) unless params['RelayState'] == ''
        result[:relay_state] = params['RelayState']
      end
      json(result)
    end

    def h(value)
      ERB::Util.html_escape(value.to_s)
    end
  end
end
