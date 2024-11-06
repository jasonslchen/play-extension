require 'sinatra'
require 'octokit'
require 'uri'
require 'net/http'
require 'json'
require 'openssl'
require 'base64'

set :port, 3000

$copilot_llm_url = "https://api.githubcopilot.com/chat/completions"
$gh_cp_public_keys = "https://api.github.com/meta/public_keys/copilot_api"

def decode_key key, signature, payload
  openssl_key = OpenSSL::PKey::EC.new(key)
  openssl_key.verify(OpenSSL::Digest::SHA256.new, Base64.decode64(signature), payload.chomp)
end

def verify_api_public_key request, payload
  signature = request.env["HTTP_GITHUB_PUBLIC_KEY_SIGNATURE"]
  key_id = request.env["HTTP_GITHUB_PUBLIC_KEY_IDENTIFIER"]
  
  # Verify public key signature
  url = URI $gh_cp_public_keys

  request = Net::HTTP::Get.new(url.path)
  http = Net::HTTP.new(url.host, url.port)
  http.use_ssl = (url.scheme == "https")
  begin
    res = http.request(request)
    if res.is_a?(Net::HTTPSuccess)
      response = JSON.parse res.body
      public_keys = response["public_keys"]
      curr_key = public_keys.find do |key|
        key["key_identifier"] == key_id
      end
      return decode_key curr_key["key"], signature, payload
    end
  rescue => e
    halt 400, "Unable to verify public key, #{e.message}"
  end
  return false
end

post "/" do
  payload = request.body.read
  auth_token = request.env["HTTP_X_GITHUB_TOKEN"]
  
  verified = verify_api_public_key(request, payload)
  
  begin
    if verified
      client = Octokit::Client.new(:access_token => auth_token)
      curr_user = client.user
      parsed_payload = JSON.parse payload
      messages = parsed_payload["messages"]
      # messages.unshift({
      #   {

      #   }
      # })
      llm_url = URI $copilot_llm_url
      req = Net::HTTP::Post.new(llm_url.path)
      http = Net::HTTP.new(llm_url.host, llm_url.port)
      http.use_ssl = llm_url.scheme == "https"
      req["Authorization"] = "Bearer #{auth_token}"
      req["Content-Type"] = "application/json"
      req.body = ({"messages" => messages, "stream" => true}).to_json
      
      stream do |out|
        http.request req do |res|
          res.read_body do |chunk|
            out << chunk
          end
        end
      end
      
    else
      status 400
      body "Unable to be verified"
    end
  rescue Octokit::Error => e
    status_code 400
    body e.message
  end
end