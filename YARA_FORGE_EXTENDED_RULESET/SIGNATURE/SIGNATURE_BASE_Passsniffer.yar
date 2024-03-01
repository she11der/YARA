import "pe"

rule SIGNATURE_BASE_Passsniffer
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file PassSniffer.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f5965aa8-0f78-56fd-8e3e-6dc013942cb3"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1915-L1933"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "dcce4c577728e8edf7ed38ac6ef6a1e68afb2c9f"
		logic_hash = "771b45473c48618c43c6be84dd37b2ccb23643f1674d437763cb78ce560067c0"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Sniff" fullword ascii
		$s3 = "GetLas" fullword ascii
		$s4 = "VersionExA" fullword ascii
		$s10 = " Only RuntUZ" fullword ascii
		$s12 = "emcpysetprintf\\" ascii
		$s13 = "WSFtartup" fullword ascii

	condition:
		all of them
}
