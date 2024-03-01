import "pe"

rule SIGNATURE_BASE_Wiltedtulip_Silverlightmsi : FILE
{
	meta:
		description = "Detects powershell tool call Get_AD_Users_Logon_History used in Operation Wilted Tulip"
		author = "Florian Roth (Nextron Systems)"
		id = "6430d464-b9c7-5f19-b89d-3c70f99af688"
		date = "2017-07-23"
		modified = "2023-12-05"
		reference = "http://www.clearskysec.com/tulip"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/apt_wilted_tulip.yar#L149-L165"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "716db8f8e7d71c7f3deaeb9ac8e141c9bf374e5dae992e8e2623070c81089953"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c75906dbc3078ff81092f6a799c31afc79b1dece29db696b2ecf27951a86a1b2"

	strings:
		$x1 = ".\\Get_AD_Users_Logon_History.ps1 -MaxEvent" fullword ascii
		$x2 = "if ((Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly -ErrorAction \"SilentlyContinue\").Type -eq \"PTR\")" fullword ascii
		$x3 = "$Client_Name = (Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly).NameHost  " fullword ascii
		$x4 = "########## Find the Computer account in AD and if not found, throw an exception ###########" fullword ascii

	condition:
		( filesize <20KB and 1 of them )
}
