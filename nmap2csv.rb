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
    File.open(file_path) do |file|
      parser = Nokogiri::XML::SAX::Parser.new(NmapSAXHandler.new(@service_results, @host_results))
      parser.parse(file)
    end
  end

  class NmapSAXHandler < Nokogiri::XML::SAX::Document
    def initialize(service_results, host_results)
      super()
      @current_host = nil
      @current_port = nil
      @current_service = nil
      @service_results = service_results
      @host_results = host_results
    end

    def start_element(name, attrs = [])
      attrs_hash = Hash[attrs]

      if name == 'host'
        @current_host = {
          ip: nil,
          hostnames: [],
          mac: nil,
          os: {
            name: nil,
            flavor: nil,
            sp: nil
          },
          mac_vendor: nil,
          ports: []
        }
      elsif name == 'address' && @current_host
        if attrs_hash['addrtype'] == 'ipv4'
          @current_host[:ip] = attrs_hash['addr']
        elsif attrs_hash['addrtype'] == 'mac'
          @current_host[:mac] = attrs_hash['addr']
          @current_host[:mac_vendor] = attrs_hash['vendor']
        end
      elsif name == 'hostname' && @current_host
        @current_host[:hostnames] << attrs_hash['name']
      elsif name == 'osmatch' && @current_host
        @current_host[:os][:name] = attrs_hash['name'] if attrs_hash['name']
      elsif name == 'osclass' && @current_host
        @current_host[:os][:sp] = attrs_hash['osgen']
      elsif name == 'port' && @current_host
        @current_port = {
          portid: attrs_hash['portid'],
          protocol: attrs_hash['protocol'],
          state: nil,
          service: nil
        }
        @current_host[:ports] << @current_port
      elsif name == 'state' && @current_port
        @current_port[:state] = attrs_hash['state']
      elsif name == 'service' && @current_port
        conf_value = attrs_hash['conf'] ? attrs_hash['conf'].to_i : 0
        @current_service = {
          name: attrs_hash['name'],
          tunnel: attrs_hash['tunnel'],
          product: attrs_hash['product'],
          version: attrs_hash['version'],
          extrainfo: attrs_hash['extrainfo'],
          conf: conf_value,
          http_title: nil
        }
        @current_port[:service] = @current_service
      elsif name == 'script' && @current_service
        if attrs_hash['id'] == 'http-title'
          @current_service[:http_title] = attrs_hash['output'] if attrs_hash['output']
        end
      end
    end

    def end_element(name)
      if name == 'host' && @current_host
        @current_host[:hostnames] = @current_host[:hostnames].join(', ')

        @host_results << {
          address: @current_host[:ip],
          mac: @current_host[:mac],
          name: @current_host[:hostnames],
          os_name: @current_host[:os][:name],
          os_flavor: @current_host[:os][:flavor],
          os_sp: @current_host[:os][:sp]
        }

        @current_host[:ports].each do |port|
          next if port[:service] && port[:service][:conf] <= 5

          @service_results << {
            ip: @current_host[:ip],
            hostnames: @current_host[:hostnames],
            mac: @current_host[:mac],
            mac_vendor: @current_host[:mac_vendor],
            os_name: @current_host[:os][:name],
            port: port[:portid],
            tcp_udp: port[:protocol],
            protocol: port[:service] ? port[:service][:name] : nil,
            state: port[:state],
            tunnel: port[:service] ? port[:service][:tunnel] : nil,
            http_title: port[:service] ? port[:service][:http_title] : nil,
            service_info: port[:service]
          }
        end

        @current_host = nil
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
      opts.banner = "Usage: nmap_cli_tool.rb [options]"

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
    deduplicated_services = deduplicate_services(parser.service_results)
    write_service_csv(deduplicated_services, services_csv_path)

    puts "[*] Writing host infos to: #{hosts_csv_path}"
    deduplicated_hosts = deduplicate_hosts(parser.host_results)
    write_hosts_csv(deduplicated_hosts, hosts_csv_path)

    puts "[*] CSV generation completed."
  end

  def self.deduplicate_services(services)
    services.uniq { |s| [s[:ip], s[:port], s[:tcp_udp], s[:protocol], s[:state], s[:tunnel]] }
  end

  def self.deduplicate_hosts(hosts)
    hosts.uniq { |h| h[:address] }
  end

  def self.write_service_csv(results, output_file)
    headers = [
      'IP-address',
      'Hostname',
      'mac',
      'mac-vendor',
      'os_name',
      'port',
      'tcp/udp',
      'protocol',
      'state',
      'tunnel',
      'http-title',
      'Info'
    ]

    CSV.open(output_file, 'w', col_sep: ';', quote_char: '"', write_headers: true, headers: headers) do |csv|
      results.each do |result|
        service_info = result[:service_info] || {}
        info = [service_info[:product], service_info[:version], service_info[:extrainfo]].compact.join(' ').strip
        csv << [
          result[:ip],
          result[:hostnames],
          result[:mac],
          result[:mac_vendor],
          result[:os_name],
          result[:port],
          result[:tcp_udp],
          result[:protocol], 
          result[:state], 
          result[:tunnel], 
          result[:http_title],
          info
        ]
      end
    end
  end

  def self.write_hosts_csv(results, output_file)
    headers = [
      'address',
      'mac',
      'name',
      'os_name',
      'os_flavor',
      'os_sp'
    ]

    CSV.open(output_file, 'w', col_sep: ';', quote_char: '"', write_headers: true, headers: headers) do |csv|
      results.each do |result|
        csv << [
          result[:address],
          result[:mac],
          result[:name],
          result[:os_name],
          result[:os_flavor],
          result[:os_sp]
        ]
      end
    end
  end
end

NmapCLI.run if __FILE__ == $PROGRAM_NAME
