# Vpn Connector © 2019 Jase Bleazard
param([string]$ConfigFile = "vpnconfig.xml")

#simple xsd schema
$xsd=@"
<?xml version="1.0" encoding="utf-8"?>
<xs:schema attributeFormDefault="unqualified" elementFormDefault="qualified" xmlns:xs="http://www.w3.org/2001/XMLSchema">
 <xs:simpleType name="NotEmptyTrimmedString">
    <xs:restriction base="xs:string">
      <xs:pattern value="^\S(.*\S)?$" />
    </xs:restriction>
  </xs:simpleType>
  <xs:element name="VPN">
	<xs:complexType>
		<xs:attribute name="name" type="NotEmptyTrimmedString" use="required" />
		<xs:attribute name="proto" type="xs:string" use="optional" />
		<xs:attribute name="address" type="xs:string" use="required" />
		<xs:attribute name="l2tppsk" type="xs:string" use="optional" />
		<xs:attribute name="user" type="xs:string" use="optional" />
		<xs:attribute name="password" type="xs:string" use="optional" />
		<xs:attribute name="connect" type="xs:boolean" use="optional" />
		<xs:attribute name="samePassword" type="xs:boolean" use="optional" />
	</xs:complexType>
  </xs:element>
</xs:schema>
"@

# C# helper code to create VPN with DotRas library
$Source = @"
	using DotRas; 
	using System; 
	using System.Xml;
	using System.Xml.Schema;
	using System.IO;

	public class VpnHelper {

		public static XmlSchema GetXsdSchema(string schema) {
			return XmlSchema.Read(new StringReader(schema), (e,args) => Console.WriteLine("XML schema error: " + args));	
		}


		static RasVpnStrategy ConvertProto(String proto) {
			if (String.IsNullOrEmpty(proto)) {
				return DotRas.RasVpnStrategy.Default;
			} else if (String.Equals(proto, "L2TP", StringComparison.OrdinalIgnoreCase)) {
				return DotRas.RasVpnStrategy.L2tpOnly;
			} else if (String.Equals(proto, "SSTP", StringComparison.OrdinalIgnoreCase)) {
				return DotRas.RasVpnStrategy.SstpOnly;
			} else if (String.Equals(proto, "IKEV2", StringComparison.OrdinalIgnoreCase)) {
				return DotRas.RasVpnStrategy.IkeV2Only;
			} else if (String.Equals(proto, "PPTP", StringComparison.OrdinalIgnoreCase)) {
				return DotRas.RasVpnStrategy.PptpOnly;
			}
		
			return DotRas.RasVpnStrategy.Default;
		}
	
	
		public static void Add(string path,string name, string server, string proto, string l2tppsk, string user, string password) {
			RasPhoneBook PhoneBook=new RasPhoneBook();

			PhoneBook.Open(path);

			RasEntry VpnEntry = RasEntry.CreateVpnEntry(name, server, ConvertProto(proto), RasDevice.Create(name, DotRas.RasDeviceType.Vpn), true);
			VpnEntry.Options.UsePreSharedKey = true;
			VpnEntry.Options.CacheCredentials = true;
			VpnEntry.Options.ReconnectIfDropped = true;
			if (VpnEntry.VpnStrategy == RasVpnStrategy.IkeV2Only) {
				VpnEntry.Options.RequireEap = true;
				VpnEntry.CustomAuthKey = 26; // 26 means eap-mschapv2 username/password
			} else { 
				VpnEntry.Options.RequireMSChap2 = true;				
			}
			
			VpnEntry.EncryptionType = RasEncryptionType.RequireMax;
			PhoneBook.Entries.Add(VpnEntry);
			VpnEntry.UpdateCredentials(RasPreSharedKey.Client, l2tppsk);
			VpnEntry.UpdateCredentials(new System.Net.NetworkCredential(user, password));
		}		
	}
"@

Add-Type -Path $psscriptroot\DotRas.dll
Add-Type -AssemblyName System.Xml
Add-Type -ReferencedAssemblies $psscriptroot\DotRas.dll,System.Xml -TypeDefinition $Source -Language CSharp  


# String coalescing helper function not available in Powershell
function Coalesce([string[]] $StringsToLookThrough, [switch]$EmptyStringAsNull) {
  if ($EmptyStringAsNull.IsPresent) {
    return ($StringsToLookThrough | Where-Object { $_ } | Select-Object -first 1)
  }
  else {
    return (($null -ne $StringsToLookThrough) | Select-Object -first 1)
  }  
}


function ValidateLoadXml([string] $XmlFile, [string] $Schema) {

	$verr={ 
		Write-Error "Error: malformed XSD/XML Line: $($_.Exception.LineNumber) Offset: $($_.Exception.LinePosition) - $($_.Message)" 
		throw [System.IO.InvalidDataException] 
	}

	try {
		[System.Xml.XmlReaderSettings]$readsett=New-Object System.Xml.XmlReaderSettings
		$readsett.Schemas.Add([System.Xml.Schema.XmlSchema]::Read((New-Object System.IO.StringReader($Schema)),$verr))
		$readsett.ValidationType=[System.Xml.ValidationType]::Schema
		$readsett.add_ValidationEventHandler($verr)
		$xmlconf = New-Object System.Xml.XmlDocument
		$xmlconf.Load([System.Xml.XmlReader]::Create($XmlFile,$readsett))
	}
	catch [System.IO.InvalidDataException]  {
		return $null
	}
	
	return $xmlconf
}

function RequestKeyInput() {
	Write-Host -NoNewLine "`nPress any key to continue . . . "
	[Console]::ReadKey($true) | Out-Null
}

Write-Host "`nVPN CONNECTION SCRIPT © 2019 Jase Bleazard"
Write-Host "---------------------------------------------`n`n"


$pbkfile="$env:APPDATA\Microsoft\Network\Connections\Pbk\rasphone.pbk"
$cfgfile=Resolve-Path $ConfigFile # Visual studio Powershell debug project uses IDE folder as working path...still to figure how to switch to $(SolutionDir)

$xmlconf=ValidateLoadXml $cfgfile $xsd # do not use comma to separate parameters otherwise the 2 strings get concatenated
if ($null -ne $xmlconf) {
	$vpn = $xmlconf.VPN
	$name = $vpn.name
	$proto = $vpn.Proto
	$serverurl = $vpn.address
	$l2tppsk = (Coalesce $vpn.l2tppsk -EmptyStringAsNull)
	$user = (Coalesce $vpn.user -EmptyStringAsNull)
	$password = (Coalesce $vpn.password -EmptyStringAsNull)
	$samePassword = $vpn.samePassword
	
	if ([string]::IsNullOrWhitespace($user) -Or [string]::IsNullOrWhitespace($password)) {
		Write-Warning "Error: Provider $name either user or password field is empty, skipping.`n"
		RequestKeyInput
		return;
	}

	if ([string]::Equals($proto, "L2TP", [StringComparison]::OrdinalIgnoreCase) -And [string]::IsNullOrWhitespace($l2tppsk)) {
		Write-Warning "Error: Provider $name L2TP/IPSEC proto selected and l2tppsk field is empty, skipping.`n"
		RequestKeyInput
		return;
	}

	$exist = Get-VpnConnection -Name $name -ErrorAction silentlycontinue
	if ($null -ne $exist) {
		Write-Host "Info: VPN Provider - $name status: $($exist.ConnectionStatus)"
		if ($exist.ConnectionStatus -eq "Connected" -Or $exist.ConnectionStatus -eq "Connecting") {
			Write-Host "Info: Connected, now disconnecting."
			$cmd = $env:WINDIR + "\System32\rasdial.exe"
			$expression = "$cmd /DISCONNECT"
			Invoke-Expression -Command $expression 
		}
		Write-Host "Info: Removing VPN connection $name"
		Remove-VpnConnection -Name $name -Force	
	}

	Write-Host "Info: Adding VPN connection Name: $name, Server: $serverurl, Protocol: $proto"
	[VpnHelper]::Add($pbkfile,$name,$serverurl,$proto,$l2tppsk,$user,$password)
	Write-Host "Info: Finished adding VPN provider."

	Write-Host "InfO: Conenct? $(-Not "false" -eq $vpn.connect)"
	if (Test-Connection -computer "www.google.com" -count 1 -quiet) {
		if (-Not ("false" -eq $vpn.connect)) {
			Write-Host "Info: Connecting..."
			if ("false" -eq $samePassword) {
				$encryptedPassword = Read-Host "Password for $user" -AsSecureString
				$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($encryptedPassword))
			}

			# TODO: Scriptify the following. Pass the xml config to the script so it has access to the
			# 		VPN config.
			# TODO: Dismount drives.

			if ($(Get-VpnConnection | Where-Object {$_.Name -eq $name}).ConnectionStatus -eq "Disconnected") {
				$cmd = $env:WINDIR + "\System32\rasdial.exe"
				$expression = "$cmd ""$name"" $user $password"
				Invoke-Expression -Command $expression 

				Write-Host "Info: Waiting for connection"
				do {
					Start-Sleep 5
				} until ($(Get-VpnConnection | Where-Object {$_.Name -eq $name}).ConnectionStatus -eq "Connected")
			}

			Write-Host "Info: Mounting Drives."
			#net use L: \\192.168.21.10\Data /user:$user $password
			#net use M: \\192.168.21.10\JoeV /user:$user $password
			#net use K: \\192.168.21.10\JoeC /user:$user $password
		}
	} else {
		Write-Host -ForegroundColor Red "ERROR: Cannot connect to the VPN if the computer isn't connected to the Internet. Please ensure your device is connected and rerun the script."
	}
}

RequestKeyInput
