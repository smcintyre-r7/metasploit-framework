# -*- coding: binary -*-

class Msf::Sessions::PowerShell < Msf::Sessions::CommandShell
  module Mixin
    #
    # Takes over the shell_command of the parent
    #
    def shell_command(cmd, timeout = 1800)
      # insert random marker
      strm = Rex::Text.rand_text_alpha(15)
      endm = Rex::Text.rand_text_alpha(15)

      waiting_for = :prompt

      # Send the shell channel's stdin.
      shell_write(";\n")
      cmd_lines = cmd.split("\n") # todo: need to track and handle a continuation prompt

      etime = ::Time.now.to_f + timeout

      buff = ''
      # Keep reading data until the marker has been received or the 30 minute timeout has occurred
      while (::Time.now.to_f < etime)
        res = shell_read(-1, timeout)
        break unless res

        timeout = etime - ::Time.now.to_f

        next unless res.rstrip =~ (/\r?PS PROMPT1MARKER2_QXuVY >$/)

        if waiting_for == :prompt
          buff = ''
          shell_write(cmd_lines.shift + "\n")
          waiting_for = :output
        elsif waiting_for == :output
          res.delete_suffix!("PS PROMPT1MARKER2_QXuVY >")
          res.delete_suffix!("\r")
          buff << res
          unless cmd_lines.empty?
            shell_write(cmd_lines.shift + "\n")
            next
          end

          break
        end
      end

      buff
    end
  end

  include Mixin

  #
  # Execute any specified auto-run scripts for this session
  #
  def process_autoruns(datastore)
    # Read the username and hostname from the initial banner
    initial_output = shell_read(-1, 2)
    if initial_output =~ /running as user ([^\s]+) on ([^\s]+)/
      username = Regexp.last_match(1)
      hostname = Regexp.last_match(2)
      self.info = "#{username} @ #{hostname}"
    elsif initial_output
      self.info = initial_output.gsub(/[\r\n]/, ' ')
    end

    # Call our parent class's autoruns processing method
    super
  end

  #
  # Returns the type of session.
  #
  def self.type
    'powershell'
  end

  def self.can_cleanup_files
    true
  end

  #
  # Returns the session platform.
  #
  def platform
    'windows'
  end

  #
  # Returns the session description.
  #
  def desc
    'Powershell session'
  end
end
