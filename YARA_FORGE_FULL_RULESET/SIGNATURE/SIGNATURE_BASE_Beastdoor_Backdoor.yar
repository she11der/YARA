import "pe"

rule SIGNATURE_BASE_Beastdoor_Backdoor
{
	meta:
		description = "Detects the backdoor Beastdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "64f67233-6677-53c8-b212-f1a425f78803"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L547-L567"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5ab10dda548cb821d7c15ebcd0a9f1ec6ef1a14abcc8ad4056944d060c49535a"
		logic_hash = "35aa5d66c0fd4bf1995fc23a68283e8a28f31b5a1e1f3b742dd0ab89c48bf403"
		score = 55
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Redirect SPort RemoteHost RPort  -->Port Redirector" fullword
		$s1 = "POST /scripts/WWPMsg.dll HTTP/1.0" fullword
		$s2 = "http://IP/a.exe a.exe            -->Download A File" fullword
		$s7 = "Host: wwp.mirabilis.com:80" fullword
		$s8 = "%s -Set Port PortNumber              -->Set The Service Port" fullword
		$s11 = "Shell                            -->Get A Shell" fullword
		$s14 = "DeleteService ServiceName        -->Delete A Service" fullword
		$s15 = "Getting The UserName(%c%s%c)-->ID(0x%s) Successfully" fullword
		$s17 = "%s -Set ServiceName ServiceName      -->Set The Service Name" fullword

	condition:
		2 of them
}
