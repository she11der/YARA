rule SIGNATURE_BASE_Wildneutron_Sample_2 : FILE
{
	meta:
		description = "Wild Neutron APT Sample Rule"
		author = "Florian Roth (Nextron Systems)"
		id = "1893c251-f81a-5361-91fa-f91a6d1379d2"
		date = "2015-07-10"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_wildneutron.yar#L36-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "8d80f9ef55324212759f4b6070cb8fce18a008ae9dd8b9598553206654d13a6f"
		logic_hash = "3a796199a2e9f2711e5fbdc1050234a8f3c09f762bc645f49a705d9f112d9cdc"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "rundll32.exe \"%s\",#1" fullword wide
		$s1 = "IgfxUpt.exe" fullword wide
		$s2 = "id-at-postalAddress" fullword ascii
		$s3 = "Intel(R) Common User Interface" fullword wide
		$s4 = "%s%s%s=%d,%s=%d,%s=%d," fullword wide
		$s11 = "Key Usage" fullword ascii
		$s12 = "Intel Integrated Graphics Updater" fullword wide
		$s13 = "%sexpires on    : %04d-%02d-%02d %02d:%02d:%02d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}
