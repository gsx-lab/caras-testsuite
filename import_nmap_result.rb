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
require 'nmap/xml'

#
# ImportNmapResult
#
class ImportNmapResult < TestCaseTemplate
  @description = 'Import nmap scan result from result directory.'
  @requires = 'Individual'
  @protocol = 'TCP/UDP'
  @author = 'Global Security Experts Inc.'

  def attack
    @console.info self, 'Ctrl+c to cancel.'

    begin
      sleep(0.1)
      nmap_result_dir = ask_nmap_result_dir
      return unless nmap_result_dir

      result = load_nmap_result nmap_result_dir

      dump_nmap_result result

      sleep(0.1)
      return unless ask_ok_or_not

      save_to_db result
    rescue Interrupt
      @console.warn self, 'Interrupted'
      return
    end
  end

  private

  #
  # ask for directory to load nmap results
  #
  def ask_nmap_result_dir
    nmap_result_dir = @path_to[:cwd].join('nmap')
    prompt = "Specify nmap result directory (#{nmap_result_dir}) > "
    loop do
      answer = @console.readline(prompt, add_history: false, allow_empty: true)

      break if answer[:line].empty?
      dir = Pathname answer[:line]
      unless dir.directory?
        @console.error self, "#{dir} is not directory."
        next
      end

      nmap_result_dir = dir
      break
    end
    nmap_result_dir
  end

  #
  # load nmap result
  #
  def load_nmap_result(nmap_result_dir)
    result = {}
    Dir.glob(nmap_result_dir.join('*')).each do |filename|
      next unless FileTest.file? filename
      if File.extname(filename) == '.xml'
        parse_xml(filename, result)
      else
        parse_text(filename, result)
      end
    end
    sort_result(result)
  end

  def parse_xml(filename, result)
    Nmap::XML.new(filename) do |xml|
      xml.find { |h| h.ip == @host.ip }&.ports&.each do |port|
        next if result[port.number] && result[port.number][:version]
        result[port.number] = xml_to_port_state(port)
      end
    end
  end

  def xml_to_port_state(port)
    {
      proto: port.protocol.to_s,
      state: port.state.to_s,
      service: port.service&.name,
      version: concat_extra_info(port)
    }
  end

  def concat_extra_info(port)
    version = [port.service&.product, port.service&.version].compact.join(' ')
    version += " (#{port.service.extra_info})" if port.service&.extra_info
    version
  end

  def parse_text(filename, result)
    File.read(filename).lines.each do |line|
      next if should_skip?(line)
      next if parse_as_sv(result, line)
      parse_as_not_sv(result, line)
    end
    result
  end

  def should_skip?(line)
    if line.start_with? 'Nmap scan report for '
      line.slice!('Nmap scan report for ')
      line.chomp!
      return line == @host.ip
    end
    line.chomp.empty?
  end

  #
  # parse line as service scan
  #
  def parse_as_sv(result, line)
    # format
    # 80/tcp  open  http  Apache HTTP Server
    return false unless /\A(\d+)\/(tcp|udp) +([^\s]+) +([^\s]+) +(.+)/ =~ line
    no = Integer(Regexp.last_match(1))
    result[no] = {
      proto: Regexp.last_match(2),
      state: Regexp.last_match(3),
      service: Regexp.last_match(4),
      version: Regexp.last_match(5)
    }
    true
  end

  #
  # parse line as not service scan
  #
  def parse_as_not_sv(result, line)
    return false unless /\A(\d+)\/(tcp|udp) +([^\s]+) +([^\s]+)/ =~ line
    no = Integer(Regexp.last_match(1))

    # skip if already have service scan result
    return false if result[no] && result[no][:version]

    result[no] = {
      proto: Regexp.last_match(2),
      state: Regexp.last_match(3),
      service: Regexp.last_match(4)
    }
    true
  end

  #
  # sort protocol and number in ascending order
  #
  def sort_result(result)
    result.sort_by do |k, v|
      [v[:proto], k]
    end
  end

  #
  # dump loaded nmap result
  #
  def dump_nmap_result(result)
    headings = %w[No. proto state service version]
    tables = %w[tcp udp].map do |proto|
      rows = result.select { |_, v| v[:proto] == proto }.map do |k, v|
        [k, v[:proto], v[:state], v[:service], v[:version]]
      end

      table = Terminal::Table.new(title: "#{proto} ports", rows: rows)
      table.headings = headings
      table
    end
    @console.info self, tables.map(&:to_s).join("\n")
  end

  #
  # confirm to load
  #
  def ask_ok_or_not
    answer = @console.readline('Import these result? [Y/n] > ', add_history: false)
    answer[:words][0] == 'Y'
  end

  #
  # save to database
  #
  def save_to_db(result)
    @host.ports.destroy_all

    result.each do |no, v|
      @host.ports.create(
        proto: v[:proto],
        no: no,
        state: v[:state],
        nmap_service: v[:service],
        nmap_version: v[:version] ? v[:version] : nil
      )
    end
    @host.update(test_status: :not_tested)
  end
end
