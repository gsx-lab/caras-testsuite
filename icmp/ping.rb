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
require 'net/ping'

#
# Icmp::Ping
#
class Ping < TestCaseTemplate
  @description = 'ping target host'
  @requires = nil
  @protocol = 'ICMP'
  @author = 'Global Security Experts Inc.'

  def attack
    cmd = "ping -c 4 #{@ip}"
    result = command(cmd, 'ping.log', ttl: 10, input: nil)
    evidence = create_evidence(@host, payload: cmd, data: result[:out])

    return unless result[:status]&.zero?

    register_vulnerability(
      evidence,
      name: 'Response to a ping',
      severity: :info,
      description: 'The host responds to a ping.'
    )
  end
end
