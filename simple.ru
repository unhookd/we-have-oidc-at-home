# Simple static http server
#
#   will emit any headers from the request in the response body as yaml
#
# bundle exec rackup simple.ru -p 8080 -o 0.0.0.0

require 'rack'
require 'yaml'

module Simple
  class Server
    def call(env)
      req = Rack::Request.new(env)
      respond_ok(req)
    end

    def respond_ok(req)
      [200, { 'content-type' => 'text/plain' }, [YAML.dump((req.each_header.collect { |k,v| "#{k}: #{v}" }))]]
    end
  end
end

run Simple::Server.new
