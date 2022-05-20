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
          ['ENUM_ALL_OBJECTCLASS', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ENUM_COMPUTERS', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['CUSTOM_QUERY', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ENUM_EXCHANGE', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ENUM_GROUPS', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ENUM_ORGROLES', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ENUM_ORGUNITS', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ENUM_PEOPLE', { 'Description' => 'Dump all objects containing any objectClass field.' }],
          ['ENUM_USERS', { 'Description' => 'Dump all objects containing any objectClass field.' }]
        ],
        'DefaultAction' => 'ENUM_ALL_OBJECTCLASS',
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
        entries = []

        if (@base_dn = datastore['BASE_DN'])
          print_status("User-specified base DN: #{@base_dn}")
        else
          print_status('Discovering base DN automatically')
          unless (@base_dn = discover_base_dn(ldap))
            print_warning("Couldn't discover base DN!")
          end
        end

        filter = Net::LDAP::Filter.construct('(objectClass=*)') # Get ALL of the objects that have any objectClass associated with them. Can return a lot of info.
        perform_ldap_query(ldap, filter, entries)
        filter = Net::LDAP::Filter.construct('(objectClass=organizationalPerson)') # Find people within an organization by Person entries.
        perform_ldap_query(ldap, filter, entries)
        filter = Net::LDAP::Filter.construct('(objectClass=organizationalUnit)') # Find OUs aka Organizational Units
        perform_ldap_query(ldap, filter, entries)
        p entries
      end
    rescue Net::LDAP::Error => e
      print_error("#{e.class}: #{e.message}")
    end
  end
end
