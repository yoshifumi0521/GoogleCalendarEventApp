#GoogleAuthSub. Class to handle google AuthSub proxy authentication.
# See detail about Google AuthSub Authentication : http://code.google.com/apis/accounts/docs/AuthSub.html
require 'uri'
require 'net/http'
require "cgi"

class GoogleAuthSubException < Exception; end


  class GoogleAuthSub

    @@google_AuthSubRequest_URI = 'https://www.google.com/accounts/AuthSubRequest'
    @@google_AuthSubSessionToken_URI = 'https://www.google.com/accounts/AuthSubSessionToken'
    @@google_AuthSubTokenInfo_URI = 'https://www.google.com/accounts/AuthSubTokenInfo'
    @ca_file = nil
    @logger = nil

    #create googleAuthSub Object.
    # token: sessionToken. It's OK token=nil but in this case you need to put it by getSessionToken before calling googleHttpGet.
    # ca_file: path to Certificate authority file in .pem format. 
    #          GoogleAuthSub works fine without this file but in this case the library connect with google server without SSL veryfication.
    # logger: logger object. You can get googleAuthSub debug log through this.
    
    #コンストラクター
    def initialize(ca_file=nil,logger=nil)
	   @ca_file = ca_file
	   @logger = logger
    end

    #genarate URL string for AuthSubRequest
    #next  	(required) URL the user should be redirected to after a successful login. This value should be a page on the web application site, and can include query parameters.
    #hd 	(optional) String value identifying a particular hosted domain account to be accessed (for example, 'mycollege.edu'). Use "default" to specify a regular Google account ('username@gmail.com').
    #scope 	(required) URL identifying the service(s) to be accessed; see documentation for the service for the correct value(s). The resulting token enables access to the specified service(s) only. To specify more than one scope, list each one separated with a space (encodes as "%20").
    #secure 	(optional) Boolean flag indicating whether the authentication transaction should issue a secure token (1) or a non-secure token (0). Secure tokens are available to registered applications only.
    
    def GoogleAuthSub.getURLForAuthSubRequest(scopeURI,nextURI,secure=nil,hd=nil)
	   param = "?scope=#{CGI.escape(scopeURI)}&next=#{CGI.escape(nextURI)}&session=1"
	   param << "&secure=#{CGI.escape(secure)}" if (secure)
	   param << "&secure=#{CGI.escape(hd)}" if (hd)
	   return (@@google_AuthSubRequest_URI + param)
    end

    def GoogleAuthSub.getOneTimeTokenFromUri(request_uri)
	   return request_uri.scan(/token=(.+)/)[0][0]
    end

    #exchange an oneTimeToken for a sessionToken.
    def getSessionToken(oneTimeToken)
	   res = googleHttpGet(@@google_AuthSubSessionToken_URI,oneTimeToken)
	   sessionToken = nil
	   case res
	     when Net::HTTPSuccess then 
		    sessionToken = res.body.scan(/Token=(.+)/)[0][0]
	     else
		    error("fail to get sessionToken. res:#{res.code}:#{res.message}")
	   end

	     return sessionToken
    end

#Test whether a given session token is valid.
#return: nil if token is invalid.
#        A hash if token is valid.
#         result['target']  
#         result['secure']
#         result['scope']
def getAuthSubTokenInfo(token)
	res = googleHttpGet(@@google_AuthSubTokenInfo_URI, token)
	result = {}
	case res
	when Net::HTTPSuccess then 
		result['target'] = res.body.scan(/Target=(.+)/)[0][0]
		result['secure'] = res.body.scan(/Secure=(.+)/)[0][0]
		result['scope'] = res.body.scan(/Scope=(.+)/)[0][0]
	else
		result = nil
	end
	return result
end

#Access google server with session token autentification.
#url: a url string you want to access.
#token: token to access. if you already set sessin token to GoogleAuthSub object, GoogleAuthSub use it.
def googleHttpGet(url,token)
	debug("googleHttpGet. url:#{url}")
	debug("googleHttpGet. token:#{token}")

	url = URI.parse(url)

	res = false
	max_retry_count = 5
	max_retry_count.times {|retry_count|
		http = Net::HTTP.new(url.host, url.port)
		if (443==url.port)
			http.use_ssl = true 
			if (@ca_file)
				http.ca_file = @ca_file
				http.verify_mode = OpenSSL::SSL::VERIFY_PEER
			else
				http.verify_mode = OpenSSL::SSL::VERIFY_NONE 
			end
			http.verify_depth = 5
		end
		params = {
			"Authorization" => %Q(AuthSub token="#{token}"),
		}
		debug("getting content from google...")

		res= http.get( url.request_uri ,params )

		debug("res:#{res.code}:#{res.message}")
		debug("res.body:#{res.body}")
		res.each{|name,value|
			debug("res[#{name}]:#{value}")
		}
	
		case res
		when Net::HTTPSuccess
			break
		when Net::HTTPRedirection
			info("#{retry_count}th redirect...new url:#{res['Location']}")
			url = URI.parse(res['Location'])
			next
		else
			error("get unexpected responce. res:#{res.code}:#{res.message}")
			break
		end
	}
	return res
end


#for debug
def fatal(msg)
	@logger.fatal(msg) if (@logger)
end
def error(msg)
	@logger.error(msg) if (@logger)
end
def warn(msg)
	@logger.warn(msg) if (@logger)
end
def info(msg)
	@logger.info(msg) if (@logger)
end
def debug(msg)
	@logger.debug(msg) if (@logger)
end

end
