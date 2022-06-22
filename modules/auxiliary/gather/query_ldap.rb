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
          This module allows users to query an LDAP server using either a custom LDAP query, or
          a set of LDAP queries under a specific category. The custom query is controlled via
          the LDAPQUERY parameter, which will be used when the ACTION value is set to CUSTOM_QUERY.

          Alternatively one can run one of several predefined queries by setting ACTION to the
          appropriate value.

          All results will be returned to the user in table format, with || as the delimeter
          seperating multiple items within one column.
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
          ['ENUM_ALL_OBJECTCATEGORY', { 'Description' => 'Dump all objects containing any objectCategory field.' }],
          ['ENUM_COMPUTERS', { 'Description' => 'Dump all objects containing an objectCategory of Computer.' }],
          ['CUSTOM_QUERY', { 'Description' => 'Execute a custom LDAP query specified by LDAPQUERY.' }],
          ['ENUM_DOMAIN_CONTROLERS', { 'Description' => 'Dump all known domain controllers.' }],
          ['ENUM_EXCHANGE_SERVERS', { 'Description' => 'Dump info about all known Exchange servers.' }],
          ['ENUM_EXCHANGE_RECIPIENTS', { 'Description' => 'Dump info about all known Exchange recipients.' }],
          ['ENUM_GROUPS', { 'Description' => 'Dump info about all known groups in the LDAP environment.' }],
          ['ENUM_ORGROLES', { 'Description' => 'Dump info about all known organizational roles in the LDAP environment.' }],
          ['ENUM_ORGUNITS', { 'Description' => 'Dump info about all known organization units in the LDAP environment.' }],
          ['ENUM_PEOPLE', { 'Description' => 'Dump info about all organizationalPerson objects.' }],
          ['ENUM_USERS', { 'Description' => 'Dump info about all known users in the LDAP environement.' }]
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

  def perform_ldap_query(ldap, filter)
    returned_entries = ldap.search(base: @base_dn, filter: filter)
    if returned_entries.nil? || returned_entries.empty?
      print_error("No results found for #{filter}. You may require additional authentication, or the information may not exist on the target.")
      [nil, nil]
    else
      [filter.to_s, returned_entries]
    end
  end

  def run
    entries = nil
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
        when 'CUSTOM_QUERY'
          unless datastore['LDAPQUERY']
            print_error('When using the CUSTOM_QUERY action one must specify the custom query via LDAPQUERY!')
            return
          end
          print_status("Querying using #{datastore['LDAPQUERY']} on #{peer}")
          # Perform custom query
          filter = Net::LDAP::Filter.construct(datastore['LDAPQUERY'])
          entries = perform_ldap_query(ldap, filter)

        # Many of the following queries came from http://www.ldapexplorer.com/en/manual/109050000-famous-filters.htm. All credit goes to them for these popular queries.
        when 'ENUM_ALL_OBJECTCLASS'
          filter = Net::LDAP::Filter.construct('(objectClass=*)') # Get ALL of the objects that have any objectClass associated with them. Can return a lot of info.
          entries = perform_ldap_query(ldap, filter)
        when 'ENUM_ALL_OBJECTCATEGORY'
          filter = Net::LDAP::Filter.construct('(objectCategory=*)') # Get ALL of the objects that have any objectCategory associated with them. Can return a lot of info.
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_COMPUTERS'
          filter = Net::LDAP::Filter.construct('(objectCategory=Computer)') # Find computers
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_DOMAIN_CONTROLERS'
          filter = Net::LDAP::Filter.construct('(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))') # Find domain controllers
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_EXCHANGE_SERVERS'
          filter = Net::LDAP::Filter.construct('(&(objectClass=msExchExchangeServer)(!(objectClass=msExchExchangeServerPolicy)))') # Find Exchange Servers
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_EXCHANGE_RECIPIENTS'
          # Find Exchange Recipients with or without fax addresses.
          filter = Net::LDAP::Filter.construct('(|(mailNickname=*)(proxyAddresses=FAX:*))')
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_GROUPS'
          # Standard LDAP groups query, followed by trying to find AD security groups, then trying to find Linux groups.
          # Filters combined to remove duplicates.
          filter = Net::LDAP::Filter.construct('(|(objectClass=group)(objectClass=groupOfNames)(groupType:1.2.840.113556.1.4.803:=2147483648)(objectClass=posixGroup))')
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_ORGUNITS'
          filter = Net::LDAP::Filter.construct('(objectClass=organizationalUnit)') # Find OUs aka Organizational Units
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_ORGROLES'
          filter = Net::LDAP::Filter.construct('(objectClass=organizationalRole)') # Find OUs aka Organizational Units
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_PEOPLE'
          filter = Net::LDAP::Filter.construct('(objectClass=organizationalPerson)') # Find people within an organization by Person entries.
          entries = perform_ldap_query(ldap, filter)

        when 'ENUM_USERS'
          # Common LDAP user query, followed by a query for AD User records by account type.
          # Finally, query for Linux accounts by objectClass.
          #
          # Doing this all in one query also prevents duplicate entires across multiple queries.
          filter = Net::LDAP::Filter.construct('(|(objectClass=inetOrgPerson)(objectClass=user)(sAMAccountType=805306368)(objectClass=posixAccount)(objectClass=GsAccount)(objectClass=GsSIPUser))')
          entries = perform_ldap_query(ldap, filter)
        end
      end
    rescue Rex::ConnectionTimeout => e
      print_error("Could not query #{datastore['RHOST']}! Error was: #{e.message}")
      return
    end

    return if entries[1].nil?

    columns = []
    entries[1].each do |entry|
      entry.attribute_names.each do |attribute|
        columns << attribute.to_s
      end
    end
    columns.uniq!
    tbl = Rex::Text::Table.new(
      'Header' => "#{action.name} Dump of #{peer}",
      'Indent' => 1,
      'Columns' => columns
    )
    entries[1].each do |entry|
      data = []
      columns.each do |col|
        col = col.to_sym
        if entry[col].nil? || entry[col].empty? || entry[col][0].empty?
          data << nil
        else
          data << entry[col].join(' || ')
        end
      end
      tbl << data
    end
    print_status(tbl.to_s)
  rescue Net::LDAP::Error => e
    print_error("#{e.class}: #{e.message}")
  end
end
