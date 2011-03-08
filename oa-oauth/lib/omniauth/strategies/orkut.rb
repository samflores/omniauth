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
				hash = user_hash
       
        OmniAuth::Utils.deep_merge(super, {
	        'uid' => hash.delete('id'),
	        'user_info' => hash,
          'extra' => {'user_hash' => user_hash}
        })
      end

      def user_info
        user_hash = self.user_hash
        {
          'name' => "#{user_hash['name']['givenName']} #{user_hash['name']['familyName']}",
          'image' => user_hash['thumbnailUrl']
        }
      end
      
      def user_hash
					@data ||= MultiJson.decode(@access_token.get('http://www.orkut.com/social/rest/people/@me/@self', {}).body)['entry']
      end
    end
  end
end
