#!/usr/bin/env ruby
require 'nokogiri'
require 'optparse'
require 'csv'
require 'fileutils'

class NmapXMLParser
  attr_reader :service_results, :host_results

  def initialize
    @service_results = []
    @host_results = []
  end

  def parse(file_path)
    doc = Nokogiri::XML(File.read(file_path))

    doc.xpath('//host').each do |host_node|
      ip = host_node.at_xpath('address[@addrtype="ipv4"]/@addr')&.value
      mac = host_node.at_xpath('address[@addrtype="mac"]/@addr')&.value
      mac_vendor = host_node.at_xpath('address[@addrtype="mac"]/@vendor')&.value
      hostnames = host_node.xpath('hostnames/hostname/@name').map(&:value)[0]
      os_name = host_node.at_xpath('os/osmatch/@name')&.value

      @host_results << {
        'IP-Address' => ip,
        'Hostname' => hostnames,
        'Mac' => mac,
        'Mac-Vendor' => mac_vendor, 
        'OS' => os_name
      }

      host_node.xpath('ports/port').each do |port_node|
        portid = port_node['portid']
        protocol = port_node['protocol']
        state = port_node.at_xpath('state/@state')&.value

        service_node = port_node.at_xpath('service')
        next unless service_node

        cpe = service_node.at_xpath('cpe')&.text

        # Grab Vulners script node
        vulners_script = port_node.at_xpath('script[@id="vulners"]')
        vulners_links = ''

        if vulners_script && cpe
          # Look for tables with matching CPE key
          cpe_table = vulners_script.xpath("table[@key='#{cpe}']")
          vuln_tables = cpe_table.xpath('table')

          links = vuln_tables.first(3).map do |vuln|
            type = vuln.at_xpath("elem[@key='type']")&.text
            id   = vuln.at_xpath("elem[@key='id']")&.text
            next unless type && id
            "https://vulners.com/#{type}/#{id}"
          end.compact

          vulners_links = links.join('\n')
        end

        @service_results << {
          'IP-Address' => ip,
          'Hostname' => hostnames,
          'Mac' => mac,
          'Mac-Vendor' => mac_vendor,
          'OS name' => os_name,
          'Port' => portid,
          'Protocol' => protocol,
          'Service' => service_node['conf'].to_i >= 5 ? service_node['name'] : 'N/A',
          'State' => state,
          'Tunnel' => service_node['tunnel'],
          'HTTP-Title' => port_node.at_xpath('script[@id="http-title"]/@output')&.value,
          'Info' => [
            service_node['product'],
            service_node['version'],
            service_node['extrainfo']
          ].compact.reject(&:empty?).join(' ').strip(),
          'CPE' => cpe,
          'Vulners' => vulners_links
        }
      end
    end
  end
end


class NmapCLI
  SERVICES_CSV_FILENAME = 'services.csv'
  HOSTS_CSV_FILENAME = 'hosts.csv'

  def self.run
    options = {}
    OptionParser.new do |opts|
      opts.banner = "Usage: nmap2csv.rb [options]"

      opts.on("-f", "--file PATH", "Path to an Nmap XML file or directory (required)") do |file|
        options[:file] = file
      end

      opts.on("-o", "--output DIR", "Directory for output CSV files (optional, default is current working directory)") do |output|
        options[:output] = output
      end

      opts.on("-h", "--help", "Prints this help") do
        puts opts
        exit
      end
    end.parse!

    if options[:file].nil?
      puts "[!] Error: Missing required --file argument."
      exit 1
    end

    output_dir = options[:output] || Dir.pwd

    parser = NmapXMLParser.new

    input_path = options[:file]
    files_to_process = []

    if File.directory?(input_path)
      puts "[*] Processing directory: #{input_path}"
      files_to_process = Dir.glob(File.join(input_path, '*.xml'))
    elsif File.file?(input_path)
      files_to_process = [input_path]
    else
      puts "[!] Error: Invalid file or directory path: #{input_path}"
      exit 1
    end

    files_to_process.each do |file|
      puts "[*] Parsing Nmap XML file: #{file}"
      parser.parse(file)
    end

    services_csv_path = File.join(output_dir, SERVICES_CSV_FILENAME)
    hosts_csv_path = File.join(output_dir, HOSTS_CSV_FILENAME)

    FileUtils.mkdir_p(File.dirname(output_dir))

    puts "[*] Writing service infos to: #{services_csv_path}"
    write_csv(parser.service_results, services_csv_path)

    puts "[*] Writing host infos to: #{hosts_csv_path}"
    write_csv(parser.host_results, hosts_csv_path)

    puts "[*] CSV generation completed."
  end
  
  def self.write_csv(results, output_file)
    return if results.empty?
    headers = results.first.keys
    CSV.open(output_file,
            'w',
            col_sep: ';',
            quote_char: '"',
            force_quotes: true,
            write_headers: true,
            headers: headers) do |csv|
      results.each do |row|
        csv << headers.map { |h| row[h] }
      end
    end
  end

end

NmapCLI.run if __FILE__ == $PROGRAM_NAME
