# Copyright 2017 Global Security Experts Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
require 'net/http'
require 'uri'

#
# Tcp::Http::DetectHttpService
#
class DetectHttpService < TestCaseTemplate
  @description = 'Http service detection'
  @requires = 'Tcp::SslConnect'
  @protocol = 'http'
  @author = 'Global Security Experts Inc.'

  def target_ports
    @host.tcp.open_ports
  end

  def attack_on_port(port)
    http, connectable = http?(port, ssl: false)
    port.update(service: 'http', plain: connectable) if http

    return unless port.ssl
    https, _connectable = http?(port, ssl: true)
    port.service = 'http' if https
    port.plain = false if https && !http
    port.save
  end

  #
  # connect and send http request
  # returns [http?] [connectable?]
  #
  def http?(port, ssl: false)
    uri = URI.parse("#{ssl ? 'https' : 'http'}://#{port.host.ip}:#{port.no}")

    send_http_request(uri, port, ssl)

    # Connection success normally
    @console.info self, "#{uri} connection success."
    return true, true
  rescue EOFError
    # No response(is not HTTP)
    @console.warn self, "#{uri} returned empty."
    return false, true
  rescue Net::HTTPBadResponse
    # Bad response(is not HTTP)
    @console.warn self, "#{uri} returned bad http response."
    return false, true
  rescue Errno::ECONNREFUSED
    # Port closed
    @console.warn self, "#{uri} refused connection."
    return false, false
  rescue Errno::ECONNRESET
    # Reset connection
    @console.warn self, "#{uri} reset connection."
    return false, nil
  rescue Timeout::Error
    # Timed out
    @console.warn self, "#{uri} connection timed out."
    return false, nil
  rescue StandardError => e
    # Unknown error
    @console.warn self, "#{uri} unknown error."
    @console.fatal self, e
    return false, nil
  end

  def send_http_request(uri, port, ssl)
    http = Net::HTTP.new(port.host.ip, port.no)
    http.use_ssl = ssl
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE if ssl
    req = Net::HTTP::Get.new(uri.request_uri)
    Timeout.timeout(5) do
      http.request(req)
    end
  end
end
