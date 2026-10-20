require 'minitest/autorun'
require 'rack'
require 'rack/mock'

require 'securerandom'
ENV['STATIC_PASSWORD'] = SecureRandom.hex(24)
ENV['REDIRECT_URIS'] = 'https://app.example.test/oauth/callback'
ENV['SAML_DEBUG'] = 'true'
Rack::Builder.parse_file(File.expand_path('../config.ru', __dir__))

class ServerTest < Minitest::Test
  HOST = 'https://one.idp.example.test'
  OTHER = 'https://two.idp.example.test'
  ACS = 'https://app.example.test/saml/acs'
  SP = 'urn:example:app'
  NS = MinimalSAML::Server::NS.merge('ds' => XMLSecurity::Document::DSIG)

  def setup
    ENV['SAML_DEBUG'] = 'true'
    @app = MinimalOIDC::Server.new
    @request = Rack::MockRequest.new(@app)
    @auth = 'Basic ' + Base64.strict_encode64("alice:#{ENV.fetch('STATIC_PASSWORD')}")
  end

  def debug_request(method, path, host: HOST, data: nil, **headers)
    options = { 'HTTP_AUTHORIZATION' => @auth }.merge(headers)
    if data
      options['CONTENT_TYPE'] = 'application/json'
      options[:input] = JSON.generate(data)
    end
    @request.request(method, host + path, options)
  end

  def create_profile(host: HOST, **overrides)
    response = debug_request('POST', '/crud/saml', host: host,
                             data: { sp_entity_id: SP, acs_url: ACS }.merge(overrides))
    assert_equal 201, response.status, response.body
    JSON.parse(response.body)
  end

  def request_xml(**overrides)
    attributes = {
      'xmlns:samlp' => MinimalSAML::Server::PROTOCOL,
      'xmlns:saml' => MinimalSAML::Server::ASSERTION,
      'ID' => '_request_123', 'Version' => '2.0', 'IssueInstant' => Time.now.utc.iso8601,
      'Destination' => "#{HOST}/saml/sso", 'AssertionConsumerServiceURL' => ACS,
      'ProtocolBinding' => MinimalSAML::Server::POST_BINDING
    }.merge(overrides.transform_keys(&:to_s))
    Nokogiri::XML::Builder.new do |xml|
      xml['samlp'].AuthnRequest(attributes) { xml['saml'].Issuer SP }
    end.to_xml
  end

  def encode_request(xml, redirect:)
    if redirect
      deflater = Zlib::Deflate.new(Zlib::DEFAULT_COMPRESSION, -Zlib::MAX_WBITS)
      begin
        xml = deflater.deflate(xml, Zlib::FINISH)
      ensure
        deflater.close
      end
    end
    Base64.strict_encode64(xml)
  end

  def login_form(xml: request_xml, redirect: true, relay: 'opaque-state', host: HOST)
    params = { 'RelayState' => relay }
    params['SAMLRequest'] = encode_request(xml, redirect: redirect) if xml
    @request.request(redirect ? 'GET' : 'POST', host + '/saml/sso', params: params)
  end

  def login(form, host: HOST, password: ENV.fetch('STATIC_PASSWORD'))
    assert_equal 200, form.status, form.body
    token = Nokogiri::HTML(form.body).at_css('input[name=login_token]')['value']
    @request.post(host + '/saml/sso', params: { login_token: token, username: 'alice', password: password })
  end

  def saml_response(page)
    assert_equal 200, page.status, page.body
    form = Nokogiri::HTML(page.body)
    assert_equal ACS, form.at_css('form')['action']
    encoded = form.at_css('input[name=SAMLResponse]')['value']
    [encoded, Nokogiri::XML(Base64.strict_decode64(encoded)), form]
  end

  def settings(config)
    OneLogin::RubySaml::Settings.new.tap do |settings|
      settings.idp_entity_id = config['idp_entity_id']
      settings.idp_cert = config['x509_certificate']
      settings.sp_entity_id = SP
      settings.assertion_consumer_service_url = ACS
      settings.security[:want_assertions_signed] = true
      settings.security[:want_messages_signed] = true
    end
  end

  def test_debug_is_opt_in_and_requires_nonempty_credentials
    ENV.delete('SAML_DEBUG')
    %w[/crud/saml /saml/consume].each do |path|
      assert_equal 404, debug_request('GET', path).status
      assert_equal 404, debug_request('POST', path, data: {}).status
    end
    ENV['SAML_DEBUG'] = 'true'
    assert_equal 401, @request.get(HOST + '/crud/saml').status
    assert_equal 401, debug_request('GET', '/crud/saml', 'HTTP_AUTHORIZATION' => 'Basic !!!').status
    app = MinimalSAML::Server.new(user: MinimalOIDC::Server::USER, password: '')
    auth = 'Basic ' + Base64.strict_encode64('alice:')
    assert_equal 401, Rack::MockRequest.new(app).get(HOST + '/crud/saml', 'HTTP_AUTHORIZATION' => auth).status
  end

  def test_hostname_scoped_crud_and_ephemeral_keys
    first = create_profile
    second = create_profile(host: OTHER)
    refute_equal first['x509_certificate'], second['x509_certificate']
    assert_equal HOST + '/saml/sso', first['idp_sso_url']
    assert_equal HOST + '/saml/metadata', first['idp_entity_id']
    assert_equal HOST + '/saml/consume', first['consumer_url']
    refute_includes JSON.generate(first), 'PRIVATE KEY'
    assert_equal first, JSON.parse(debug_request('GET', '/crud/saml').body)
    updated = debug_request('POST', '/crud/saml', data: { name_id: 'bob@example.test' })
    assert_equal 200, updated.status
    assert_equal first['x509_certificate'], JSON.parse(updated.body)['x509_certificate']
    assert_equal 'bob@example.test', JSON.parse(updated.body)['name_id']
    assert_equal second, JSON.parse(debug_request('GET', '/crud/saml', host: OTHER).body)
    assert_equal 204, debug_request('POST', '/crud/saml', data: { action: 'delete' }).status
    assert_equal 400, debug_request('GET', '/crud/saml').status
    refute_equal first['x509_certificate'], create_profile['x509_certificate']
    assert_equal 204, debug_request('DELETE', '/crud/saml').status
    assert_equal 404, debug_request('DELETE', '/crud/saml').status
    fresh = Rack::MockRequest.new(MinimalOIDC::Server.new)
    assert_equal 400, fresh.get(HOST + '/saml/metadata').status
  end

  def test_generated_consumer_and_explicit_public_origin
    response = debug_request('POST', '/crud/saml', data: { sp_entity_id: SP, idp_base_url: HOST + ':8443/' })
    assert_equal 201, response.status
    config = JSON.parse(response.body)
    assert_equal HOST + ':8443/saml/consume', config['acs_url']
    assert_equal HOST + ':8443/saml/sso', config['idp_sso_url']
    assert_equal config, JSON.parse(debug_request('GET', '/saml/consume').body)['settings']
  end

  def test_invalid_profiles_and_cross_origin_mutations
    [
      {}, { sp_entity_id: [] }, { sp_entity_id: SP, acs_url: 'javascript:alert(1)' },
      { sp_entity_id: SP, acs_url: 'https://user@example.test' },
      { sp_entity_id: SP, idp_base_url: OTHER }, { sp_entity_id: SP, attributes: [] },
      { sp_entity_id: SP, attributes: { 'email' => { 'nested' => 'value' } } },
      { sp_entity_id: SP, unknown: 'value' }
    ].each do |data|
      assert_equal 400, debug_request('POST', '/crud/saml', data: data).status
    end
    assert_equal 400, debug_request('POST', '/crud/saml', data: { sp_entity_id: SP }, 'HTTP_ORIGIN' => OTHER).status
    assert_equal 400, debug_request('DELETE', '/crud/saml', 'HTTP_SEC_FETCH_SITE' => 'cross-site').status
    assert_equal 400, @request.post(HOST + '/crud/saml', 'HTTP_AUTHORIZATION' => @auth,
                                   'CONTENT_TYPE' => 'application/json', input: '{').status
    response = @request.post(HOST + '/crud/saml', 'HTTP_AUTHORIZATION' => @auth, params: { sp_entity_id: SP })
    assert_equal 201, response.status
  end

  def test_metadata_and_certificate_are_consistent
    config = create_profile
    response = @request.get(HOST + '/saml/metadata')
    assert_equal 200, response.status
    doc = Nokogiri::XML(response.body)
    namespaces = { 'md' => MinimalSAML::Server::METADATA, 'ds' => XMLSecurity::Document::DSIG }
    assert_equal config['idp_entity_id'], doc.root['entityID']
    services = doc.xpath('//md:SingleSignOnService', namespaces)
    assert_equal 2, services.size
    assert services.all? { |service| service['Location'] == config['idp_sso_url'] }
    cert = OpenSSL::X509::Certificate.new(config['x509_certificate'])
    assert cert.verify(cert.public_key)
    assert_equal cert.to_der, Base64.strict_decode64(doc.at_xpath('//ds:X509Certificate', namespaces).text)
    assert_equal cert.to_pem, @request.get(HOST + '/saml/certificate').body
  end

  def test_redirect_login_produces_a_valid_signed_saml_response
    config = create_profile(attributes: { 'email' => 'alice@example.test', 'groups' => %w[users admins] })
    encoded, doc, form = saml_response(login(login_form))
    assert_equal 'opaque-state', form.at_css('input[name=RelayState]')['value']
    assert_equal '_request_123', doc.root['InResponseTo']
    assert_equal ACS, doc.root['Destination']
    assert_equal SP, doc.at_xpath('//saml:Audience', NS).text
    assert_equal 2, doc.xpath('//ds:Signature', NS).size
    assert doc.xpath('//ds:SignatureMethod', NS).all? { |node| node['Algorithm'] == XMLSecurity::Document::RSA_SHA256 }
    result = OneLogin::RubySaml::Response.new(encoded, settings: settings(config), matches_request_id: '_request_123')
    assert result.is_valid?, result.errors.join(', ')
    assert_equal 'alice@example.com', result.name_id
    assert_equal %w[users admins], result.attributes.multi('groups')
    verify_xml_signatures(doc, OpenSSL::X509::Certificate.new(config['x509_certificate']))
    altered = Base64.strict_encode64(Base64.strict_decode64(encoded).sub('alice@example.com', 'mallory@example.com'))
    refute OneLogin::RubySaml::Response.new(altered, settings: settings(config)).is_valid?
  end

  def verify_xml_signatures(doc, certificate)
    doc.xpath('//ds:Signature', NS).each_with_index do |_, index|
      copy = doc.dup
      signature = copy.xpath('//ds:Signature', NS)[index]
      signed_info = signature.at_xpath('./ds:SignedInfo', NS)
      signature_value = Base64.strict_decode64(signature.at_xpath('./ds:SignatureValue', NS).text)
      canonical = signed_info.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0)
      assert certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature_value, canonical)
      digest = signed_info.at_xpath('./ds:Reference/ds:DigestValue', NS).text
      prefixes = signed_info.at_xpath('.//*[local-name()="InclusiveNamespaces"]')['PrefixList'].split
      reference = signed_info.at_xpath('./ds:Reference', NS)['URI']
      target = copy.at_xpath('//*[@ID=$id]', nil, id: reference.delete_prefix('#'))
      signature.remove
      canonical = target.canonicalize(Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0, prefixes)
      assert_equal digest, Base64.strict_encode64(OpenSSL::Digest::SHA256.digest(canonical))
    end
  end

  def test_post_binding_and_idp_initiated_login
    config = create_profile
    encoded, = saml_response(login(login_form(redirect: false)))
    result = OneLogin::RubySaml::Response.new(encoded, settings: settings(config))
    assert result.is_valid?, result.errors.join(', ')
    encoded, doc, = saml_response(login(login_form(xml: nil)))
    assert_nil doc.root['InResponseTo']
    assert_nil doc.at_xpath('//saml:SubjectConfirmationData', NS)['InResponseTo']
    result = OneLogin::RubySaml::Response.new(encoded, settings: settings(config))
    assert result.is_valid?, result.errors.join(', ')
  end

  def test_authentication_replay_and_cross_host_protection
    create_profile
    create_profile(host: OTHER)
    form = login_form
    assert_equal 401, login(form, password: 'wrong').status
    assert_equal 400, login(form).status
    form = login_form
    assert_equal 400, login(form, host: OTHER).status
    form = login_form
    assert_equal 200, login(form).status
    assert_equal 400, login(form).status
    form = login_form
    debug_request('POST', '/crud/saml', data: { acs_url: 'https://new.example.test/acs' })
    assert_equal 400, login(form).status
  end

  def test_rejects_untrusted_authn_request_routing
    create_profile
    [
      request_xml(AssertionConsumerServiceURL: 'https://attacker.example.test/acs'),
      request_xml(Destination: OTHER + '/saml/sso'),
      request_xml(ProtocolBinding: MinimalSAML::Server::REDIRECT_BINDING),
      request_xml(Version: '1.1'), request_xml(ID: ''),
      request_xml(IssueInstant: (Time.now - 600).utc.iso8601),
      request_xml(IsPassive: 'true'), request_xml(AssertionConsumerServiceIndex: '1'),
      request_xml.sub(SP, 'urn:other:sp'), request_xml.sub('AuthnRequest', 'LogoutRequest')
    ].each do |xml|
      assert_equal 400, login_form(xml: xml).status
    end
  end

  def test_malformed_oversized_and_dtd_messages_are_rejected
    create_profile
    ['', '!', 'not-base64', 'a' * (MinimalSAML::Server::MAX_INPUT + 1)].each do |value|
      assert_equal 400, @request.post(HOST + '/saml/sso', params: { SAMLRequest: value }).status
    end
    ['<!DOCTYPE root [<!ENTITY a SYSTEM "file:///etc/passwd">]><root>&a;</root>',
     '<broken', 'x' * (MinimalSAML::Server::MAX_XML + 1)].each do |xml|
      assert_equal 400, login_form(xml: xml).status
      assert_equal 400, login_form(xml: xml, redirect: false).status
    end
    assert_equal 400, @request.get(HOST + '/saml/sso', params: { SAMLRequest: ['nested'] }).status
    assert_equal 400, login_form(relay: ['nested']).status
  end

  def test_debug_consumer_never_authenticates_and_escapes_html
    create_profile(name_id: 'alice<debug>@example.test')
    page = login(login_form(relay: '"><script>alert(1)</script>'))
    encoded, _, form = saml_response(page)
    assert_empty form.css('script')
    %w[GET POST].each do |method|
      response = debug_request(method, '/saml/consume', params: { SAMLResponse: encoded, RelayState: 'opaque' })
      assert_equal 200, response.status
      result = JSON.parse(response.body)
      assert_equal false, result['verified']
      assert_includes result['saml_response_xml'], 'Response'
      assert_equal 'opaque', result['relay_state']
      assert_equal 'no-store', response['cache-control']
      assert_nil response['set-cookie']
    end
  end

  def test_oidc_discovery_password_and_authorization_code_still_work
    discovery = @request.get(HOST + '/.well-known/openid-configuration')
    assert_equal 200, discovery.status
    assert_equal HOST + '/authorize', JSON.parse(discovery.body)['authorization_endpoint']
    assert_equal 200, @request.get(HOST + '/jwks.json').status
    password_response = @request.post(HOST + '/token', params: {
      grant_type: 'password', username: 'alice', password: ENV.fetch('STATIC_PASSWORD')
    })
    assert_equal 200, password_response.status
    token = JSON.parse(password_response.body)['access_token']
    info = @request.get(HOST + '/userinfo', 'HTTP_AUTHORIZATION' => 'Bearer ' + token)
    assert_equal 200, info.status
    params = { response_type: 'code', client_id: 'minimal-client', redirect_uri: ENV.fetch('REDIRECT_URIS'), state: 'state' }
    assert_equal 200, @request.get(HOST + '/authorize', params: params).status
    response = @request.post(HOST + '/authorize', params: params.merge(username: 'alice', password: ENV.fetch('STATIC_PASSWORD')))
    assert_equal 302, response.status
    code = URI.decode_www_form(URI(response['location']).query).to_h['code']
    params = { grant_type: 'authorization_code', code: code, redirect_uri: ENV.fetch('REDIRECT_URIS'),
               client_id: 'minimal-client', client_secret: MinimalOIDC::Server::CLIENTS['minimal-client'][:secret] }
    assert_equal 200, @request.post(HOST + '/token', params: params).status
    assert_equal 400, @request.post(HOST + '/token', params: params).status
  end
end
