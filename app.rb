require 'bundler/setup'
require 'sinatra'
require 'slim'
require 'sinatra/reloader'
require 'openid_connect'
require 'httparty'
require 'jwt'

class App < Sinatra::Base
  # relevant variables from environment
  set :host, ENV['host']
  set :secret, ENV['secret']
  set :prefix, '/auth/realms/srt/protocol/openid-connect'
  set :lobby, ENV['lobby']

  set server: 'thin', connections: []
  enable :sessions

  configure :development do
    require 'pry'
    register Sinatra::Reloader
  end

  get '/' do
    @session = session
    if @session.has_key? :userinfo
      @userinfo = @session[:userinfo]
    end
    slim :index, :layout => :layout
  end

  get '/lobby' do
    validate_session(session)
    @session = session
    @userinfo = session[:userinfo]
    slim :lobby
  end

  get '/login' do
    # set up the oauth client
    auth_client = oauth_client
    session_randoms(session)
    authorization_uri = auth_client.authorization_uri(
      scope: [:profile, :email],
      state: session[:state],
      nonce: session[:nonce]
    )

    redirect to(authorization_uri)
  end

  get '/login-after' do
    # Authorization Response
    code = params[:code]

    # gets the access token and sets up the session
    puts 'getting the access token and setting up the session'
    code_access(code)

    redirect to('/lobby')
  end

  get '/logout' do
    puts "logging out #{session[:userinfo]["preferred_username"]}"
    logout_url = session[:logout_url]
    session.delete(:logout_url)
    session.delete(:userinfo)
    redirect to(logout_url)
  end

  get '/chat', provides: 'text/event-stream' do
    stream :keep_open do |out|
      settings.connections << out
      out.callback { settings.connections.delete(out) }
    end
  end

  post '/chat-message' do
    settings.connections.each { |out| out << "data: #{params[:msg]}\n\n" }
    204 # response without entity body
  end

  private

  def oauth_client
    OpenIDConnect::Client.new(
      identifier: 'account',
      secret: settings.secret,
      redirect_uri: "#{settings.lobby}/login-after",
      host: settings.host,
      authorization_endpoint: "#{settings.prefix}/auth",
      token_endpoint: "#{settings.prefix}/token",
      userinfo_endpoint: "#{settings.prefix}/userinfo"
    )
  end

  def session_randoms(session)
    session[:state] = SecureRandom.hex(16)
    session[:nonce] = SecureRandom.hex(16)
  end

  def validate_session(session)
    # if no session data, redirect to homepage
    # probably want some kind of flash message
    unless (session.key? :userinfo) &&
           (session.key? :logout_url) &&
           (session.key? :refresh_token)
      puts 'no session data so redirecting'
      redirect to('/')
    end

    # check if the user's refresh token is expired
    if Time.now > Time.at(JWT.decode(session[:refresh_token], nil, false)[0]['exp'])
      puts "user #{session[:userinfo].preferred_username} session expired"
      session.delete(:logout_url)
      session.delete(:userinfo)
      session.delete(:refresh_token)
      redirect to('/login')
    end

    # refresh token is not expired, so go ahead and refresh it
    puts "user #{session[:userinfo].preferred_username} refreshing access token"
    refresh_access(session[:refresh_token])
  end

  def code_access(code)
    auth_client = oauth_client
    auth_client.authorization_code = code
    access_token = auth_client.access_token! # => OpenIDConnect::AccessToken
    update_session(access_token)
  end

  def refresh_access(refresh_token)
    auth_client = oauth_client
    auth_client.refresh_token = refresh_token
    access_token = auth_client.access_token! # => OpenIDConnect::AccessToken
    update_session(access_token)
  end

  def update_session(access_token)
    # certs_response = JSON.parse(HTTParty.get("https://#{settings.host}#{settings.prefix}/certs").body)
    # public_key = JSON::JWK.new(certs_response["keys"].first).to_key
    # id_token = OpenIDConnect::ResponseObject::IdToken.decode access_token.id_token, public_key # => OpenIDConnect::ResponseObject::IdToken

    redirect_uri = CGI.escape(settings.lobby)
    session[:logout_url] = "https://#{settings.host}#{settings.prefix}/logout?redirect_uri=#{redirect_uri}"
    session[:userinfo] = access_token.userinfo!
    session[:refresh_token] = access_token.refresh_token

    puts "user #{session[:userinfo].preferred_username} refresh expires "\
      "#{Time.at(JWT.decode(session[:refresh_token], nil, false)[0]['exp'])}"
  end
end
