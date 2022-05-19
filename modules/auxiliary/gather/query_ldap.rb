##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::LDAP

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'LDAP Query and Enumeration Module',
        'Description' => %q{
          This module allows users to query an LDAP server using either a custom LDAP query, or a set of LDAP queries under a specific category.
          The custom query is controlled via the LDAPQUERY parameter, or if one wants to run a set of predefined queries they can use the PREDEFINEDQUERY
          option to specify a set of predefined queries to run.

          All results will be returned to the user as plain text.
        },
        'Author' => [
          'Grant Willcox', # Module
        ],
        'References' => [
        ],
        'DisclosureDate' => '2022-05-19',
        'License' => MSF_LICENSE,
        'Actions' => [
          ['ALL', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['COMPUTERS', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['CUSTOM', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['EXCHANGE', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['GROUPS', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ORGROLES', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ORGUNITS', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['PEOPLE', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['USERS', { 'Description' => 'Dump all objects containing any objectClass field.' }]
        ],
        'DefaultAction' => 'ALL',
        'DefaultOptions' => {
          'SSL' => false
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options([
      Opt::RPORT(389), # Set to 636 for SSL/TLS
      OptString.new('BASE_DN', [false, 'LDAP base DN if you already have it']),
      OptString.new('LDAPQUERY', [false, 'Query to run against the target LDAP server'])
    ])
  end

  def perform_ldap_query(ldap, filter, entries)
    returned_entries = ldap.search(base: @base_dn, filter: filter)
    p returned_entries
    if returned_entries.nil? || returned_entries.empty?
      print_error("No results found for #{filter}")
    else
      entries << [filter.to_s, returned_entries]
    end
  end

  def run
    entries = []

    begin
      ldap_connect do |ldap|
        if (@base_dn = datastore['BASE_DN'])
          print_status("User-specified base DN: #{@base_dn}")
        else
          print_status('Discovering base DN automatically')

          unless (@base_dn = discover_base_dn(ldap))
            print_warning("Couldn't discover base DN!")
          end
        end

        case action.name
        when 'CUSTOM'
          unless datastore['LDAPQUERY']
            print_error('When using the CUSTOM action one must specify the custom query via LDAPQUERY!')
            return
          end
          print_status("Querying using #{datastore['LDAPQUERY']} on #{peer}")
          # Perform custom query
          filter = Net::LDAP::Filter.construct(datastore['LDAPQUERY'])
          perform_ldap_query(ldap, filter, entries)

        # Many of the following queries came from http://www.ldapexplorer.com/en/manual/109050000-famous-filters.htm. All credit goes to them for these popular queries.
        when 'ALL'
          filter = Net::LDAP::Filter.construct('(objectClass=*)') # Get ALL of the objects that have any objectClass associated with them. Can return a lot of info.
          perform_ldap_query(ldap, filter, entries)

        when 'COMPUTERS'
          filter = Net::LDAP::Filter.construct('(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))') # Find domain controllers
          perform_ldap_query(ldap, filter, entries)

          filter = Net::LDAP::Filter.construct('(objectCategory=Computer)') # Find computers
          perform_ldap_query(ldap, filter, entries)

        when 'EXCHANGE'
          filter = Net::LDAP::Filter.construct('(&(objectClass=msExchExchangeServer)(!(objectClass=msExchExchangeServerPolicy)))') # Find Exchange Servers
          perform_ldap_query(ldap, filter, entries)
          filter = Net::LDAP::Filter.construct('(mailNickname=*)') # Find Exchange Recipients
          perform_ldap_query(ldap, filter, entries)
          # filter = Net::LDAP::Filter.construct("(&(msExchHideFromAddressLists=TRUE)(!objectClass=publicFolder))") # Find Exchange Recipients - hidden
          # perform_ldap_query(ldap, filter, entries)
          filter = Net::LDAP::Filter.construct('(proxyAddresses=FAX:*)') # Find Exchange Recipients - with FAX address
          perform_ldap_query(ldap, filter, entries)

        when 'GROUPS'
          filter = Net::LDAP::Filter.construct('(|(objectClass=group)(objectClass=groupOfNames))') # Standard LDAP groups query.
          perform_ldap_query(ldap, filter, entries)

          filter = Net::LDAP::Filter.construct('(groupType:1.2.840.113556.1.4.803:=2147483648)') # Find security groups within an AD environment.
          perform_ldap_query(ldap, filter, entries)

          filter = Net::LDAP::Filter.construct('(objectClass=posixGroup)') # Find Linux groups
          perform_ldap_query(ldap, filter, entries)

        when 'ORGUNITS'
          filter = Net::LDAP::Filter.construct('(objectClass=organizationalUnit)') # Find OUs aka Organizational Units
          perform_ldap_query(ldap, filter, entries)

        when 'ORGROLES'
          filter = Net::LDAP::Filter.construct('(objectClass=organizationalRole)') # Find OUs aka Organizational Units
          perform_ldap_query(ldap, filter, entries)

        when 'PEOPLE'
          filter = Net::LDAP::Filter.construct('(objectClass=organizationalPerson)') # Find people within an organization by Person entries.
          perform_ldap_query(ldap, filter, entries)

        when 'USERS'
          filter = Net::LDAP::Filter.construct('(|(objectClass=inetOrgPerson)(objectClass=user))') # Common LDAP user query.
          perform_ldap_query(ldap, filter, entries)

          filter = Net::LDAP::Filter.construct('(sAMAccountType=805306368)') # Common AD User query by account type.
          perform_ldap_query(ldap, filter, entries)

          filter = Net::LDAP::Filter.construct('(objectClass=posixAccount)') # Query for Linux accounts.
          perform_ldap_query(ldap, filter, entries)
        end
      end
    rescue Rex::ConnectionTimeout => e
      print_error("Could not query #{datastore['RHOST']}! Error was: #{e.message}")
      return
    end

    p entries # XXX probably still need to improve output formatting here.
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
  end
end
