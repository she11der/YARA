import "pe"

rule SIGNATURE_BASE_Mimikatz_Gen_Strings : FILE
{
	meta:
		description = "Detects Mimikatz by using some special strings"
		author = "Florian Roth (Nextron Systems)"
		id = "3f4ab5d7-5a9f-55f0-9dda-e2975df582a0"
		date = "2017-06-19"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-hacktools.yar#L3654-L3676"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "371e74538a63cfe355ebd31e1ac73cd25e92f3a7ce3f9299e0f3406f2bcb5b01"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash1 = "058cc8b3e4e4055f3be460332a62eb4cbef41e3a7832aceb8119fd99fea771c4"
		hash2 = "eefd4c038afa0e80cf6521c69644e286df08c0883f94245902383f50feac0f85"
		hash3 = "f35b589c1cc1c98c4c4a5123fd217bdf0d987c00d2561992cbfb94bd75920159"

	strings:
		$s1 = "[*] '%s' service already started" fullword wide
		$s2 = "** Security Callback! **" fullword wide
		$s3 = "Try to export a software CA to a crypto (virtual)hardware" fullword wide
		$s4 = "enterpriseadmin" fullword wide
		$s5 = "Ask debug privilege" fullword wide
		$s6 = "Injected =)" fullword wide
		$s7 = "** SAM ACCOUNT **" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <12000KB and 1 of them )
}
