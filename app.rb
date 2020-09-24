require 'bundler/setup'
require 'sinatra'
require 'slim'
require "sinatra/reloader"
require 'openid_connect'
require 'httparty'

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

  get "/" do
    @session = session
    if @session.has_key? :userinfo
      @userinfo = @session[:userinfo]
    end
    slim :index, :layout => :layout
  end

  get "/lobby" do
    validate_session(session)
    @session = session
    @userinfo = session[:userinfo]
    slim :lobby
  end

  get "/login" do
    # set up the oauth client
    auth_client = get_oauth_client
    set_session_randoms(session)
    authorization_uri = auth_client.authorization_uri(
      scope: [:profile, :email],
      state: session[:state],
      nonce: session[:nonce]
    )

    redirect to(authorization_uri)
  end

  get "/login-after" do
    certs_response = JSON.parse(HTTParty.get("https://#{settings.host}#{settings.prefix}/certs").body)
    public_key = JSON::JWK.new(certs_response["keys"].first).to_key
  
    # Authorization Response
    code = params[:code]
  
    # Token Request
    auth_client = get_oauth_client
    auth_client.authorization_code = code
    access_token = auth_client.access_token! # => OpenIDConnect::AccessToken
    id_token = OpenIDConnect::ResponseObject::IdToken.decode access_token.id_token, public_key # => OpenIDConnect::ResponseObject::IdToken

    redirect_uri = CGI.escape(settings.lobby)
    session[:logout_url] = "https://#{settings.host}#{settings.prefix}/logout?redirect_uri=#{redirect_uri}"
    session[:userinfo] = access_token.userinfo!

    redirect to('/lobby')
  end

  get '/logout' do
    logout_url = session[:logout_url]
    session.delete(:logout_url)
    session.delete(:userinfo)
    redirect to(logout_url)
  end

  private

  def get_oauth_client
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

  def set_session_randoms(session)
    session[:state] = SecureRandom.hex(16)
    session[:nonce] = SecureRandom.hex(16)
  end

  def validate_session(session)
    redirect to('/') unless ( ( session.has_key? :userinfo ) && ( session.has_key? :logout_url ))
  end

end