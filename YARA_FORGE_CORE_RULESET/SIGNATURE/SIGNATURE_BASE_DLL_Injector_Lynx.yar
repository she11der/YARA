import "pe"

rule SIGNATURE_BASE_DLL_Injector_Lynx : FILE
{
	meta:
		description = "Detects Lynx DLL Injector"
		author = "Florian Roth (Nextron Systems)"
		id = "7a4c9949-c701-5ae2-a8b1-3ef0b08c1c04"
		date = "2017-08-20"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/gen_loaders.yar#L78-L100"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "1904b152c42126abd87671747dc2733e2a5e2a01ab55346c131fb430fe5ba58e"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d594f60e766e0c3261a599b385e3f686b159a992d19fa624fad8761776efa4f0"

	strings:
		$x1 = " -p <TARGET PROCESS NAME> | -u <DLL PAYLOAD> [--obfuscate]" fullword wide
		$x2 = "You've selected to inject into process: %s" fullword wide
		$x3 = "Lynx DLL Injector" fullword wide
		$x4 = "Reflective DLL Injector" fullword wide
		$x5 = "Failed write payload: %lu" fullword wide
		$x6 = "Failed to start payload: %lu" fullword wide
		$x7 = "Injecting payload..." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <800KB and 1 of them ) or (3 of them )
}
