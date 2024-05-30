# Define the input XML file and output CSV files
$xmlFile = "path_to_your_xml_file.xml"
$csvFileRules = "output_rules.csv"
$csvFileAddresses = "output_addresses.csv"
$csvFileServices = "output_services.csv"
$tmshScriptFile = "output_tmsh_script.txt"

# Load the XML file
[xml]$xml = Get-Content $xmlFile

# Function to join XML elements
function Join-XmlElements {
    param (
        [Parameter(Mandatory = $true)]
        $elements
    )
    if ($elements -is [System.Xml.XmlNodeList] -or $elements -is [System.Array]) {
        return ($elements | ForEach-Object { $_.InnerText }) -join ", "
    } else {
        return $elements
    }
}

# Initialize TMSH script content and lists
$tmshScript = @()
$addressLists = @{}
$portLists = @{}

# Create CSV files and write the headers
Set-Content -Path $csvFileRules -Value "Rule Name,vsys,Source Zone,Destination Zone,Source Address,Destination Address,Application,Action"
Set-Content -Path $csvFileAddresses -Value "Address Name,vsys,Type,Value,Description"
Set-Content -Path $csvFileServices -Value "Service Name,vsys,Protocol,Port,Description"

# Extract and write address objects, and populate address lists
foreach ($vsys in $xml.config.devices.entry.vsys.entry) {
    $vsysName = $vsys.name
    foreach ($address in $vsys."address"."entry") {
        $addressName = $address.name
        if ($address."ip-netmask") {
            $type = "IP-Netmask"
            $value = $address."ip-netmask"
        } elseif ($address."ip-range") {
            $type = "IP-Range"
            $value = $address."ip-range"
        } elseif ($address.fqdn) {
            $type = "FQDN"
            $value = $address.fqdn
        } else {
            $type = "Unknown"
            $value = ""
        }
        $description = $address.description

        # Create a CSV line for addresses
        $csvLineAddress = "$addressName,$vsysName,$type,$value,$description"
        Add-Content -Path $csvFileAddresses -Value $csvLineAddress

        # Add to address lists dictionary
        $addressLists[$addressName] = $true

        # Generate TMSH commands for address objects
        if ($type -eq "IP-Netmask" -or $type -eq "IP-Range") {
            $tmshScript += "create security firewall address-list $addressName { addresses add { $value } }"
        } elseif ($type -eq "FQDN") {
            $tmshScript += "create security firewall fqdn $addressName { name $value }"
        }
    }
}

# Extract and write service objects, and populate port lists
foreach ($vsys in $xml.config.devices.entry.vsys.entry) {
    $vsysName = $vsys.name
    foreach ($service in $vsys."service"."entry") {
        $serviceName = $service.name
        if ($service."protocol"."tcp") {
            $protocol = "tcp"
            $port = $service."protocol"."tcp"."port"
        } elseif ($service."protocol"."udp") {
            $protocol = "udp"
            $port = $service."protocol"."udp"."port"
        } else {
            $protocol = "unknown"
            $port = ""
        }
        $description = $service.description

        # Create a CSV line for services
        $csvLineService = "$serviceName,$vsysName,$protocol,$port,$description"
        Add-Content -Path $csvFileServices -Value $csvLineService

        # Add to port lists dictionary
        $portLists[$serviceName] = $true

        # Generate TMSH commands for service objects
        if ($protocol -ne "unknown") {
            $tmshScript += "create security firewall port-list $serviceName { ports add { $port } }"
        }
    }
}

# Extract and write security rules, checking for missing address and port lists
foreach ($vsys in $xml.config.devices.entry.vsys.entry) {
    $vsysName = $vsys.name
    $policyName = "${vsysName}_policy"
    $tmshScript += "create security firewall policy $policyName"

    foreach ($rule in $vsys."rulebase"."security"."rules"."entry") {
        $ruleName = $rule.name
        $sourceZone = Join-XmlElements -elements $rule.from.member
        $destinationZone = Join-XmlElements -elements $rule.to.member
        $sourceAddress = Join-XmlElements -elements $rule.source.member
        $destinationAddress = Join-XmlElements -elements $rule.destination.member
        $application = Join-XmlElements -elements $rule.application.member
        $action = $rule.action

        # Translate actions
        if ($action -eq "allow") {
            $action = "accept"
        } elseif ($action -eq "deny") {
            $action = "drop"
        }

        # Check for missing address and port lists, excluding "any"
        if ($sourceAddress -ne "any" -and -not $addressLists.ContainsKey($sourceAddress)) {
            Write-Error "Missing address list for source address: $sourceAddress"
            exit 1
        }
        if ($destinationAddress -ne "any" -and -not $addressLists.ContainsKey($destinationAddress)) {
            Write-Error "Missing address list for destination address: $destinationAddress"
            exit 1
        }
        if ($application -ne "any" -and -not $portLists.ContainsKey($application)) {
            Write-Error "Missing port list for application: $application"
            exit 1
        }

        # Determine if the application is a port list or a direct port
        $serviceCmd = if ($application -ne "any") {
            if ($portLists.ContainsKey($application)) {
                "port-lists add { $application }"
            } else {
                "ports add { $application }"
            }
        } else {
            "ports add { any }"
        }

        # Create a CSV line for rules
        $csvLineRule = "$ruleName,$vsysName,$sourceZone,$destinationZone,$sourceAddress,$destinationAddress,$application,$action"
        Add-Content -Path $csvFileRules -Value $csvLineRule

        # Generate TMSH commands for security rules
        $tmshScript += "modify security firewall policy $policyName rules add { $ruleName { action $action source { addresses add { $sourceAddress } } destination { addresses add { $destinationAddress } } $serviceCmd } }"
    }
}

# Save TMSH script to file
Set-Content -Path $tmshScriptFile -Value $tmshScript

Write-Output "Conversion complete. CSV files saved as $csvFileRules, $csvFileAddresses, $csvFileServices. TMSH script saved as $tmshScriptFile"