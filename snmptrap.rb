require "logstash/outputs/base"
require "logstash/namespace"

class LogStash::Outputs::Snmptrap < LogStash::Outputs::Base
	config_name "snmptrap"
	milestone 1
	
	#address of the host to send the trap to
	config :host, :validate => :string, :default => "0.0.0.0"

	#the port to send the trap on
	config :port, :validate => :number, :default => 162

	#the community string to include
	config :community, :validate => :string, :default => "public"

	#the OID that specifies the event generating the trap message
	config :oid, :validate => :string, :default => "changeme"

	def initialize(*args)
		super(*args)
	end

	public
	def register
		require "snmp"
		#from snmp trap input plugin
                if @yamlmibdir
                  @logger.info("checking #{@yamlmibdir} for MIBs")
                  Dir["#{@yamlmibdir}/*.yaml"].each do |yamlfile|
                    mib_name = File.basename(yamlfile, ".*")
                    @yaml_mibs ||= []
                    @yaml_mibs << mib_name
                  end
                  @logger.info("found MIBs: #{@yaml_mibs.join(',')}") if @yaml_mibs
                end
        end 
	
	public
	def receive(event)
		return unless output?(event)
		if event == LogStash::SHUTDOWN
			finished
			return
		end
		#we got an event, do something!
		#set some variables for the trap sender
		trapsender_opts = {:trap_port => @port, :host => @host, :community => @community }
		#check for and add user specified mibs
		if !@yaml_mibs.empty?
			trapsender_opts.merge!({:mib_dir => @yamlmibdir, :mib_modules => @yaml_mibs})
		end
		SNMP::Manager.open(@trapsender_opts) do |snmp|
			#set it up and send the whole event as json for now
			varbind = VarBind.new(@oid, OctetString.new(event.to_json)
			snmp.set(@varbind)
			#we dont actually care about the sys_up_time...do we
			snmp.trap_v2(12345, @oid, @varbind)
		end
	end
end
