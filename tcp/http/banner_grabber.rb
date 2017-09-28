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

#
# Tcp::Http::BannerGrabber
#
class BannerGrabber < TestCaseTemplate
  @description = 'HTTP Banner Grabber'
  @requires = 'Tcp::Http::DetectHttpService'
  @protocol = 'http'
  @author = 'Global Security Experts Inc.'

  REQUESTS = [
    "HEAD / HTTP/1.0\n\n"
  ].freeze

  BANNER_PATTERNS = [
    /^Server:.+\n/,
    /^X-Powered-By:.+\n/
  ].freeze

  def target_ports
    @host.tcp.service('http').or(@host.tcp.service('https'))
  end

  def attack_on_port(port)
    REQUESTS.each do |request|
      get_banners(port, request)
    end
  end

  private

  def get_banners(port, request)
    connect_and_send(port, false, request) if port.plain?
    connect_and_send(port, true, request) if port.ssl?
  end

  def connect_and_send(port, ssl, request)
    url = "#{ssl ? 'https' : 'http'}://#{port.host.ip}:#{port.no}/"
    TCPSocket.open(port.host.ip, port.no) do |tcp_socket|
      begin
        ssl_socket = nil
        if ssl
          ssl_socket = OpenSSL::SSL::SSLSocket.new(tcp_socket)
          ssl_socket.connect
          socket = ssl_socket
        else
          socket = tcp_socket
        end
        send_request(port, socket, url, request)
      ensure
        ssl_socket&.close
      end
    end
  end

  def send_request(port, socket, url, request)
    socket.write(request)
    response = socket.read
    create_evidence(port, payload: url + "\n\n" + request, data: response)
    detect_version_string(port, url, response)
  end

  def detect_version_string(port, url, response)
    return nil unless response
    header = response.split("\n\n")[0]
    unless header
      @console.debug(self, url + "\n" + response)
      return nil
    end

    BANNER_PATTERNS.each do |pattern|
      detected = pattern.match(header)
      next unless detected
      banner = detected[0].chomp

      @console.debug(self, url + ' : ' + banner)

      register_evidences(port, banner, url)
    end
  end

  def register_evidences(port, banner, url)
    register_banner(port, banner)
    evidence = create_evidence(port, payload: url, data: banner)
    register_vulnerability(
      evidence,
      name: 'Banner disclosure',
      severity: :info,
      description: 'Disclosing banners may cause to awake an attacker'
    )
  end
end
