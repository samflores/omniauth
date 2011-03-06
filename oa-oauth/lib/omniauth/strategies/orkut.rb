require 'omniauth/oauth'
require 'multi_json'

module OmniAuth
  module Strategies
    class Orkut < OAuth
      def initialize(app, consumer_key, consumer_secret, options = {})
				options[:site] = 'https://www.google.com'
        options[:request_token_path] = '/accounts/OAuthGetRequestToken'
        options[:access_token_path] = '/accounts/OAuthGetAccessToken'
        options[:authorize_path] = '/accounts/OAuthAuthorizeToken'
        options[:scheme] = :header
        super(app, :orkut, consumer_key, consumer_secret, options)
      end
      
      def request_phase
        request_token = consumer.get_request_token({ :oauth_callback => callback_url }, {:scope => 'https://orkut.gmodules.com/social/rest'})
        (session[:oauth]||={})[name.to_sym] = {:callback_confirmed => request_token.callback_confirmed?, :request_token => request_token.token, :request_secret => request_token.secret}
        r = Rack::Response.new
        r.redirect request_token.authorize_url
        r.finish
      end
      
      def auth_hash
				hash = user_hash(@access_token)
       
        OmniAuth::Utils.deep_merge(super, {
	        'uuid' => hash.delete('id'),
	        'user_info' => hash
        })
      end
      
      def user_hash(access_token)
					@data ||= MultiJson.decode(access_token.get('http://www.orkut.com/social/rest/people/@me/@self', {}).body)['entry']
      end
    end
  end
end
