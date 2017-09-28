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
# Tcp::SslConnect
#
class SslConnect < TestCaseTemplate
  @description = 'Test to connect to all open ports with ssl.'
  @requires = nil
  @protocol = 'SSL/TLS'
  @author = 'Global Security Experts Inc.'

  def target_ports
    @host.tcp
  end

  def attack_on_port(port)
    ssl_state, tcp_state, cn = test_ssl(@host.ip, port.no)
    port.update(ssl: ssl_state, state: tcp_state ? 'open' : 'closed')
    return unless !cn.nil? && @host.hostnames.where(name: cn).count.zero?
    @host.hostnames.create(name: cn)
  end

  private

  def test_ssl(ip, port_no)
    message_prefix = "#{ip}:#{port_no} "

    ssl_state, tcp_state, cn = connect_with_ssl(ip, port_no)

    # Connection success normally
    @console.info self, "#{message_prefix}connection success : #{cn}"
    return ssl_state, tcp_state, cn
  rescue Timeout::Error
    # Timed out : SSL false, TCP unknown
    @console.warn self, "#{message_prefix}ssl timed out"
    return false, tcp_state
  rescue OpenSSL::SSL::SSLError
    # SSL connection error : SSL false, TCP true
    @console.warn self, "#{message_prefix}ssl connection error"
    return false, true
  rescue Errno::ECONNREFUSED
    # TCP connection error : SSL false, TCP false
    @console.warn self, "#{message_prefix}tcp connection error"
    return false, false
  rescue Errno::ECONNRESET
    # TCP connection reset : SSL false, TCP true
    @console.warn self, "#{message_prefix}ssl connection reset"
    return false, true
  rescue StandardError => e
    # Unknown error : SSL false, TCP unknown
    @console.warn self, "#{message_prefix}unknown error"
    @console.fatal self, e
    return false, tcp_state
  end

  def connect_with_ssl(ip, port_no)
    ssl_state, tcp_state = false
    cn = nil
    Timeout.timeout(5) do
      begin
        soc = TCPSocket.new(ip, port_no)
        tcp_state = true
        ssl = OpenSSL::SSL::SSLSocket.new(soc)
        ssl.connect

        ssl_state = true
        cn = get_hostname_from_cert(ssl)
      ensure
        ssl&.close
        soc&.close
      end
    end
    [ssl_state, tcp_state, cn]
  end

  def get_hostname_from_cert(ssl)
    cn = ssl.peer_cert.subject.to_a.select { |a| a[0] == 'CN' }
    cn[0] && cn[0][1] ? cn[0][1] : nil
  end
end
