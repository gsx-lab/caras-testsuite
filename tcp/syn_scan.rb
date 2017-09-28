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
require 'nmap'

#
# Tcp::SynScan
#
class SynScan < TestCaseTemplate
  @description = 'Syn Scan'
  @requires = 'Individual'
  @protocol = 'TCP'
  @author = 'Global Security Experts Inc.'

  def attack
    @data_dir.mkpath unless @data_dir.exist?
    xml_file = @data_dir.join('syn_scan.xml')
    syn_scan(xml_file)
    store(xml_file)
  end

  private

  def syn_scan(xml_file)
    Nmap::Program.scan(
      syn_scan: true,
      service_scan: true,
      xml: xml_file,
      targets: @host.ip
    )
  end

  def store(xml_file)
    Nmap::XML.new(xml_file) do |xml|
      xml.find { |h| h.ip == @host.ip }&.ports&.each do |port|
        create_or_update(port)
      end
    end
  end

  def create_or_update(port)
    keys = port_keys(port)
    target_port = @host.ports.find_by(keys)
    if target_port
      target_port.update(port_attributes(port))
    else
      @host.ports.create(keys.merge(port_attributes(port)))
    end
  end

  def port_keys(port)
    {
      proto: port.protocol.to_s,
      no: port.number
    }
  end

  def port_attributes(port)
    {
      state: port.state.to_s,
      nmap_service: port.service.name,
      nmap_version: concat_extra_info(port)
    }
  end

  def concat_extra_info(port)
    version = [port.service.product, port.service.version].compact.join(' ')
    version += " (#{port.service.extra_info})" if port.service.extra_info
    version
  end
end
