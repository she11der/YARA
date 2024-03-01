rule VOLEXITY_Trojan_Golang_Pantegana : Commodity
{
	meta:
		description = "Detects PANTEGANA, a Golang backdoor used by a range of threat actors due to its public availability."
		author = "threatintel@volexity.com"
		id = "b6154165-68e0-5986-a0cf-5631d369c230"
		date = "2022-03-30"
		modified = "2022-07-28"
		reference = "https://github.com/elleven11/pantegana"
		source_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/2022/2022-06-15 DriftingCloud - Zero-Day Sophos Firewall Exploitation and an Insidious Breach/indicators/yara.yar#L75-L99"
		license_url = "https://github.com/volexity/threat-intel/blob/ae4bcf3413927d976bf3f8ee107bd928c575aded/LICENSE.txt"
		logic_hash = "791a664a6b4b98051cbfacb451099de085cbab74d73771709377ab68a5a23d2b"
		score = 75
		quality = 80
		tags = ""
		hash1 = "8297c99391aae918f154077c61ea94a99c7a339166e7981d9912b7fdc2e0d4f0"
		license = "See license at https://github.com/volexity/threat-intel/blob/main/LICENSE.txt"
		memory_suitable = 1

	strings:
		$s1 = "RunFingerprinter" ascii
		$s2 = "SendSysInfo" ascii
		$s3 = "ExecAndGetOutput" ascii
		$s4 = "RequestCommand" ascii
		$s5 = "bindataRead" ascii
		$s6 = "RunClient" ascii
		$magic = "github.com/elleven11/pantegana" ascii

	condition:
		5 of ($s*) or $magic
}
