# Define the input XML file and output CSV files
$xmlFile = "config.xml"
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

# Initialize TMSH script content
$tmshScript = @()

# Create CSV files and write the headers
Set-Content -Path $csvFileRules -Value "Rule Name,vsys,Source Zone,Destination Zone,Source Address,Destination Address,Application,Action"
Set-Content -Path $csvFileAddresses -Value "Address Name,vsys,Type,Value,Description"
Set-Content -Path $csvFileServices -Value "Service Name,vsys,Protocol,Port,Description"

# Extract and write security rules
foreach ($vsys in $xml.config.devices.entry.vsys.entry) {
    $vsysName = $vsys.name
    foreach ($rule in $vsys."rulebase"."security"."rules"."entry") {
        $ruleName = $rule.name
        $sourceZone = Join-XmlElements -elements $rule.from.member
        $destinationZone = Join-XmlElements -elements $rule.to.member
        $sourceAddress = Join-XmlElements -elements $rule.source.member
        $destinationAddress = Join-XmlElements -elements $rule.destination.member
        $application = Join-XmlElements -elements $rule.application.member
        $action = $rule.action

        # Create a CSV line for rules
        $csvLineRule = "$ruleName,$vsysName,$sourceZone,$destinationZone,$sourceAddress,$destinationAddress,$application,$action"
        Add-Content -Path $csvFileRules -Value $csvLineRule

        # Generate TMSH commands for security rules
        $tmshScript += "create security firewall rule $ruleName { action $action from-zone $sourceZone to-zone $destinationZone source-address-list { $sourceAddress } destination-address-list { $destinationAddress } service { $application } }"
    }
}

# Extract and write address objects
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

        # Generate TMSH commands for address objects
        if ($type -eq "IP-Netmask" -or $type -eq "IP-Range") {
            $tmshScript += "create net address-list $addressName { addresses add { $value } }"
        } elseif ($type -eq "FQDN") {
            $tmshScript += "create net fqdn $addressName { name $value }"
        }
    }
}

# Extract and write service objects
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

        # Generate TMSH commands for service objects
        if ($protocol -ne "unknown") {
            $tmshScript += "create ltm policy rule $serviceName { requires { ltm } controls { forward } action { forward } match { protocol $protocol destination-port $port } description `"$description`" }"
        }
    }
}

# Save TMSH script to file
Set-Content -Path $tmshScriptFile -Value $tmshScript

Write-Output "Conversion complete. CSV files saved as $csvFileRules, $csvFileAddresses, $csvFileServices. TMSH script saved as $tmshScriptFile"
