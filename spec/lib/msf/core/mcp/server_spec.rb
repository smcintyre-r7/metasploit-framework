# frozen_string_literal: true

require 'msf/core/mcp'

RSpec.describe Msf::MCP::Server do
  let(:valid_config) do
    {
      msf_api: {
        type: 'messagepack',
        host: 'localhost',
        port: 55553,
        endpoint: '/api/',
        user: 'test_user',
        password: 'test_password'
      },
      rate_limit: {
        requests_per_minute: 60,
        burst_size: 10
      }
    }
  end

  let(:mock_msf_client) do
    instance_double(Msf::MCP::Metasploit::Client).tap do |client|
      allow(client).to receive(:shutdown)
    end
  end

  let(:rate_limiter) do
    Msf::MCP::Security::RateLimiter.new(
      requests_per_minute: valid_config.dig(:rate_limit, :requests_per_minute) || 60,
      burst_size: valid_config.dig(:rate_limit, :burst_size)
    )
  end

  let(:mock_mcp_server) do
    instance_double(::MCP::Server).tap do |server|
      allow(server).to receive(:transport=)
    end
  end

  let(:mock_transport) do
    instance_double(::MCP::Server::Transports::StdioTransport).tap do |transport|
      allow(transport).to receive(:open)
    end
  end

  describe '#initialize' do
    it 'initializes with required dependencies' do
      # Mock the transport to prevent the server to actually start listening
      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)

      server = described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
      mcp_server = server.start

      expect(mcp_server.server_context[:msf_client]).to eq(mock_msf_client)
      expect(mcp_server.server_context[:rate_limiter]).to eq(rate_limiter)
    end

    it 'creates MCP server with correct parameters' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          name: 'msfmcp',
          version: Msf::MCP::Application::VERSION,
          tools: be_an(Array),
          server_context: be_a(Hash)
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'registers all MCP tools' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          tools: array_including(
            Msf::MCP::Tools::SearchModules,
            Msf::MCP::Tools::ModuleInfo,
            Msf::MCP::Tools::HostInfo,
            Msf::MCP::Tools::ServiceInfo,
            Msf::MCP::Tools::VulnerabilityInfo,
            Msf::MCP::Tools::NoteInfo,
            Msf::MCP::Tools::CredentialInfo,
            Msf::MCP::Tools::LootInfo
          )
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'creates server context with msf_client and rate_limiter' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_including(
            msf_client: mock_msf_client,
            rate_limiter: rate_limiter
          )
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'does not include config hash in server_context' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_not_including(:config)
        )
      ).and_return(mock_mcp_server)

      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end
  end

  describe '#start' do
    let(:server) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    context 'with stdio transport' do
      it 'creates stdio transport' do
        expect(::MCP::Server::Transports::StdioTransport).to receive(:new).with(mock_mcp_server).and_return(mock_transport)

        server.start(transport: :stdio)
      end

      it 'sets transport on mcp_server' do
        allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(mock_transport)

        expect(mock_mcp_server).to receive(:transport=).with(mock_transport)

        server.start(transport: :stdio)
      end

      it 'opens the transport' do
        allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(mock_transport)

        expect(mock_transport).to receive(:open)

        server.start(transport: :stdio)
      end

      it 'defaults to stdio when no transport specified' do
        expect(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(mock_transport)

        server.start
      end
    end

    context 'with http transport' do
      let(:mock_http_transport) do
        instance_double(::MCP::Server::Transports::StreamableHTTPTransport)
      end
      let(:puma_handler) { double('puma_handler') }
      let(:rack_app) { double('rack_app') }

      before do
        # Stub #require to prevent actually loading rack and rack/handler/puma
        allow(server).to receive(:require).with('rack').and_return(true)
        allow(server).to receive(:require).with('rack/handler/puma').and_return(true)

        stub_const('Rack::Handler::Puma', puma_handler)
        stub_const('Rack::Builder', double('Rack::Builder'))

        allow(::MCP::Server::Transports::StreamableHTTPTransport).to receive(:new).and_return(mock_http_transport)
        allow(Rack::Builder).to receive(:new).and_return(rack_app)

        allow(puma_handler).to receive(:run)
      end

      it 'creates http transport' do
        expect(::MCP::Server::Transports::StreamableHTTPTransport).to receive(:new).with(mock_mcp_server)

        server.start(transport: :http, port: 3000)
      end

      it 'sets transport on mcp_server' do
        expect(mock_mcp_server).to receive(:transport=).with(mock_http_transport)

        server.start(transport: :http, port: 3000)
      end

      it 'starts Puma server via Rack handler' do
        expect(puma_handler).to receive(:run).with(
          anything,  # Rack app
          hash_including(
            Port: 3000,
            Host: 'localhost'
          )
        )

        server.start(transport: :http, port: 3000)
      end

      it 'allows custom port' do
        expect(puma_handler).to receive(:run).with(
          anything,
          hash_including(Port: 8080)
        )

        server.start(transport: :http, port: 8080)
      end

      it 'creates a Rack application' do
        expect(puma_handler).to receive(:run) do |rack_app, options|
          expect(rack_app).to be(rack_app)
          expect(options).to include(Port: 3000, Host: 'localhost')
        end

        server.start(transport: :http, port: 3000)
      end
    end

    context 'with invalid transport' do
      it 'raises ArgumentError' do
        expect {
          server.start(transport: :websocket)
        }.to raise_error(ArgumentError, /Unknown transport.*websocket/)
      end

      it 'error message mentions valid transports' do
        expect {
          server.start(transport: :invalid)
        }.to raise_error(ArgumentError, /stdio.*http/)
      end
    end
  end

  describe '#shutdown' do
    let(:server) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end

    it 'shuts down the Metasploit client' do
      expect(mock_msf_client).to receive(:shutdown)

      server.shutdown
    end

    it 'handles nil msf_client gracefully' do
      server.instance_variable_set(:@msf_client, nil)

      expect { server.shutdown }.not_to raise_error
    end

    it 'clears mcp_server reference' do
      server.shutdown

      expect(server.instance_variable_get(:@mcp_server)).to be_nil
    end

    it 'can be called multiple times safely' do
      expect {
        server.shutdown
        server.shutdown
      }.not_to raise_error
    end
  end

  describe 'dependency injection' do
    let(:server) do
      # Create server with pre-authenticated client
      described_class.new(
        msf_client: mock_msf_client,
        rate_limiter: rate_limiter
      )
    end
    let(:mcp_server) { server.start }

    before do
      # Mock the transport to prevent the server to actually start listening
      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)
    end

    it 'uses the provided authenticated client' do
      # The provided client should be used
      expect(mcp_server.server_context[:msf_client]).to eq(mock_msf_client)
      expect(mcp_server.server_context[:msf_client].object_id).to eq(mock_msf_client.object_id)
    end

    it 'passes the provided client to server_context' do
      expect(::MCP::Server).to receive(:new).with(
        hash_including(
          server_context: hash_including(
            msf_client: mock_msf_client
          )
        )
      ).and_return(mock_mcp_server)

      server
    end

    context 'with a custom rate limiter' do
      let(:rate_limiter) do
        Msf::MCP::Security::RateLimiter.new(
          requests_per_minute: 120,
          burst_size: 20
        )
      end

      it 'uses the provided rate_limiter' do
        expect(mcp_server.server_context[:rate_limiter]).to eq(rate_limiter)
        expect(mcp_server.server_context[:rate_limiter].instance_variable_get(:@requests_per_minute)).to eq(120)
        expect(mcp_server.server_context[:rate_limiter].instance_variable_get(:@burst_size)).to eq(20)
      end
    end
  end

  # Instrumentation and logging tests
  describe 'instrumentation and logging' do
    require 'tempfile'

    let(:log_file) { Tempfile.new(['test_log', '.log']).tap(&:close).path }

    # Wire a Rex flatfile sink for the duration of each example.
    before do
      deregister_log_source(Msf::MCP::LOG_SOURCE) if log_source_registered?(Msf::MCP::LOG_SOURCE)
      register_log_source(Msf::MCP::LOG_SOURCE, Rex::Logging::Sinks::Flatfile.new(log_file), Rex::Logging::LEV_0)

      transport = instance_double(MCP::Server::Transports::StdioTransport)
      allow(::MCP::Server::Transports::StdioTransport).to receive(:new).and_return(transport)
      allow(transport).to receive(:open)
    end

    after do
      deregister_log_source(Msf::MCP::LOG_SOURCE) if log_source_registered?(Msf::MCP::LOG_SOURCE)
      File.delete(log_file) if File.exist?(log_file)
    end

    let(:server) { described_class.new(msf_client: mock_msf_client, rate_limiter: rate_limiter) }
    let(:mcp_server) { server.start }

    describe 'instrumentation_callback' do
      it 'is always configured as a Proc' do
        expect(mcp_server.configuration.instrumentation_callback).to be_a(Proc)
      end

      it 'is a no-op when called with nil' do
        expect { mcp_server.configuration.instrumentation_callback.call(nil) }.not_to raise_error
      end

      it 'logs errors with [e] severity code' do
        mcp_server.configuration.instrumentation_callback.call(
          method: 'tools/call', tool_name: 'test_tool', error: 'tool_not_found', duration: 0.123
        )
        content = File.read(log_file)
        expect(content).to match(/\[e\(\d\)\]/)
        expect(content).to include('MCP Error: tool_not_found')
        expect(content).to include('test_tool')
      end

      it 'logs successful tool calls with [i] severity code' do
        mcp_server.configuration.instrumentation_callback.call(
          method: 'tools/call', tool_name: 'search_modules', duration: 0.456
        )
        content = File.read(log_file)
        expect(content).to match(/\[i\(\d\)\]/)
        expect(content).to include('Tool call: search_modules')
        expect(content).to include('456')
      end

      it 'includes duration in milliseconds' do
        mcp_server.configuration.instrumentation_callback.call(
          method: 'tools/call', tool_name: 'test_tool', duration: 1.23456
        )
        expect(File.read(log_file)).to include('1234.56ms')
      end

      it 'logs prompt calls' do
        mcp_server.configuration.instrumentation_callback.call(
          method: 'prompts/get', prompt_name: 'exploit_suggestion', duration: 0.123
        )
        content = File.read(log_file)
        expect(content).to include('Prompt call: exploit_suggestion')
        expect(content).to include('123.0ms')
      end

      it 'logs resource calls' do
        mcp_server.configuration.instrumentation_callback.call(
          method: 'resources/read', resource_uri: 'msf://exploits/windows', duration: 0.089
        )
        expect(File.read(log_file)).to include('Resource call: msf://exploits/windows')
      end

      it 'logs generic method calls' do
        mcp_server.configuration.instrumentation_callback.call(method: 'ping', duration: 0.001)
        expect(File.read(log_file)).to include('Method call: ping')
      end

      it 'logs fallback message when no specific key is present' do
        mcp_server.configuration.instrumentation_callback.call(some_unknown_key: 'value')
        expect(File.read(log_file)).to include('MCP instrumentation')
      end

      it 'omits duration text when not present' do
        mcp_server.configuration.instrumentation_callback.call(tool_name: 'msf_host_info')
        content = File.read(log_file)
        expect(content).to include('Tool call: msf_host_info')
        expect(content).not_to match(/\d+(\.\d+)?ms/)
      end

      it 'includes extra data keys in the log line' do
        mcp_server.configuration.instrumentation_callback.call(
          tool_name: 'msf_search_modules', custom_key: 'custom_value', another_key: 42
        )
        content = File.read(log_file)
        expect(content).to include('custom_value')
        expect(content).to include('42')
      end
    end

    describe 'exception_reporter' do
      it 'is always configured as a Proc' do
        expect(mcp_server.configuration.exception_reporter).to be_a(Proc)
      end

      it 'is a no-op when called with nil arguments' do
        expect { mcp_server.configuration.exception_reporter.call(nil, nil) }.not_to raise_error
      end

      it 'logs exceptions with [e] severity' do
        mcp_server.configuration.exception_reporter.call(
          StandardError.new('Something went wrong'),
          { request: { name: 'msf_search_modules', arguments: { 'name' => 'test_tool' } } }
        )
        content = File.read(log_file)
        expect(content).to match(/\[e\(\d\)\]/)
        expect(content).to include('Error during request processing')
        expect(content).to include('msf_search_modules')
        expect(content).to include('Something went wrong')
      end

      it 'includes exception class and message in the log line' do
        mcp_server.configuration.exception_reporter.call(
          ArgumentError.new('Invalid argument provided'),
          { request: { name: 'msf_search_modules', arguments: {} } }
        )
        content = File.read(log_file)
        expect(content).to include('ArgumentError')
        expect(content).to include('Invalid argument provided')
      end

      it 'logs notification context' do
        mcp_server.configuration.exception_reporter.call(
          RuntimeError.new('Notification failed'),
          { notification: 'notifications/initialized' }
        )
        content = File.read(log_file)
        expect(content).to include('Error during notification processing')
        expect(content).to include('notifications/initialized')
        expect(content).to include('Notification failed')
      end

      it 'logs unknown context type' do
        mcp_server.configuration.exception_reporter.call(StandardError.new('Unknown error'), {})
        content = File.read(log_file)
        expect(content).to include('Error during unknown processing')
        expect(content).to include('Unknown error')
      end

      it 'handles a non-Hash request value' do
        mcp_server.configuration.exception_reporter.call(
          StandardError.new('Parse error'), { request: 'not valid Hash' }
        )
        content = File.read(log_file)
        expect(content).to include('Error during request processing')
        expect(content).to include('not valid Hash')
      end
    end
  end

  describe 'HTTP request/response logging' do
    require 'tempfile'
    require 'json'
    require 'rack'

    let(:log_file) { Tempfile.new(['test_log', '.log']).tap(&:close).path }
    let(:server) do
      allow(::MCP::Server).to receive(:new).and_return(mock_mcp_server)
      described_class.new(msf_client: mock_msf_client, rate_limiter: rate_limiter)
    end

    before do
      deregister_log_source(Msf::MCP::LOG_SOURCE) if log_source_registered?(Msf::MCP::LOG_SOURCE)
      register_log_source(Msf::MCP::LOG_SOURCE, Rex::Logging::Sinks::Flatfile.new(log_file), Rex::Logging::LEV_0)
    end

    after do
      deregister_log_source(Msf::MCP::LOG_SOURCE) if log_source_registered?(Msf::MCP::LOG_SOURCE)
      File.delete(log_file) if File.exist?(log_file)
    end

    describe '#log_http_request' do
      it 'logs POST method, id, and params' do
        body = StringIO.new({ 'method' => 'tools/call', 'id' => 42, 'params' => { 'name' => 'test' } }.to_json)
        request = instance_double(Rack::Request, post?: true, get?: false, body: body)

        server.send(:log_http_request, request)

        content = File.read(log_file)
        expect(content).to match(/\[i\(\d\)\]/)
        expect(content).to include('HTTP Request: tools/call (id: 42)')
        expect(content).to match(/"name"\s?=>\s?"test"/)
      end

      it 'logs a warning for invalid JSON in POST body' do
        body = StringIO.new('not valid json{{{')
        request = instance_double(Rack::Request, post?: true, get?: false, body: body)

        server.send(:log_http_request, request)

        expect(File.read(log_file)).to match(/\[w\(\d\)\].*Invalid JSON in HTTP request/)
      end

      it 'logs GET SSE connection with session_id from header' do
        request = instance_double(Rack::Request,
          post?: false, get?: true,
          env: { 'HTTP_MCP_SESSION_ID' => 'abc-123', 'QUERY_STRING' => '' }
        )

        server.send(:log_http_request, request)

        content = File.read(log_file)
        expect(content).to include('SSE connection request')
        expect(content).to include('abc-123')
      end

      it 'logs GET SSE connection with session_id from query string' do
        request = instance_double(Rack::Request,
          post?: false, get?: true,
          env: { 'QUERY_STRING' => 'sessionId=xyz-789' }
        )

        server.send(:log_http_request, request)

        expect(File.read(log_file)).to include('xyz-789')
      end

      it 'does not log non-POST/GET requests' do
        request = instance_double(Rack::Request, post?: false, get?: false)
        server.send(:log_http_request, request)
        expect(File.read(log_file)).to be_empty
      end
    end

    describe '#log_http_response' do
      it 'logs POST response errors with [e] severity' do
        request = instance_double(Rack::Request, post?: true, get?: false)
        response_body = { 'error' => { 'message' => 'Method not found', 'code' => -32601 } }.to_json

        server.send(:log_http_response, request, [400, {}, [response_body]])

        content = File.read(log_file)
        expect(content).to match(/\[e\(\d\)\]/)
        expect(content).to include('HTTP Response error: Method not found')
        expect(content).to include('-32601')
      end

      it 'logs SSE accepted response' do
        request = instance_double(Rack::Request, post?: true, get?: false)
        server.send(:log_http_response, request, [202, {}, [{ 'accepted' => true }.to_json]])
        expect(File.read(log_file)).to include('Response sent via SSE stream')
      end

      it 'logs successful POST response with id and session' do
        request = instance_double(Rack::Request, post?: true, get?: false)
        server.send(:log_http_response, request,
          [200, { 'Mcp-Session-Id' => 'sess-456' }, [{ 'id' => 42, 'result' => {} }.to_json]])

        content = File.read(log_file)
        expect(content).to include('HTTP Response: success (id: 42)')
        expect(content).to include('sess-456')
      end

      it 'logs a warning for invalid JSON in POST response' do
        request = instance_double(Rack::Request, post?: true, get?: false)
        server.send(:log_http_response, request, [200, {}, ['not json{{']])
        expect(File.read(log_file)).to match(/\[w\(\d\)\].*Invalid JSON in HTTP response/)
      end

      it 'logs SSE stream established for 200 GET' do
        request = instance_double(Rack::Request, post?: false, get?: true)
        server.send(:log_http_response, request, [200, {}, []])
        expect(File.read(log_file)).to include('SSE stream established')
      end

      it 'does not log anything for empty POST body' do
        request = instance_double(Rack::Request, post?: true, get?: false)
        server.send(:log_http_response, request, [200, {}, []])
        expect(File.read(log_file)).to be_empty
      end

      it 'does not log anything for non-array body' do
        request = instance_double(Rack::Request, post?: true, get?: false)
        server.send(:log_http_response, request, [200, {}, 'string body'])
        expect(File.read(log_file)).to be_empty
      end
    end
  end
end
