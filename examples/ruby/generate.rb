# Generate an auditable password from Ruby by shelling out to
# secretgenerator. The CLI prints a stable JSON envelope (schema v1).
#
# This snippet pins the schema version so any future incompatible
# change fails loudly instead of silently changing field shapes.
#
# Install once:
#   brew install rafaelperoco/tap/secretgenerator
#   # or: npm install -g @secretgenerator/cli

require "json"
require "open3"

def generate_password(length: 24)
  stdout, status = Open3.capture2(
    "secretgenerator", "password",
    "--json",
    "--require-schema-version=1",
    "--show-crack-time",
    "--length", length.to_s,
    "--charset", "alphanum-symbols-v1"
  )
  raise "secretgenerator exited #{status.exitstatus}" unless status.success?
  JSON.parse(stdout)
end

result = generate_password(length: 24)
puts "password: #{result['password']}"
puts "entropy:  #{result['entropy_bits'].round(1)} bits"
nation_state = result["crack_time_estimates"].find { |e| e["profile_id"] == "nation-state-v1" }
puts "crack:    #{nation_state['human_readable']} (nation-state)"
