rule SIGNATURE_BASE_Rombertik_Carbongrabber : FILE
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik - file Copy#064046.scr"
		author = "Florian Roth (Nextron Systems)"
		id = "b3aee336-9f3b-5fae-928d-8357408a7b69"
		date = "2015-05-05"
		modified = "2023-12-05"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/crime_rombertik_carbongrabber.yar#L10-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "ddc3ebcc460909a4afc9994cae53c9b7642f92ab6f16e2653f6b2d5002a33cda"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "2f9b26b90311e62662c5946a1ac600d2996d3758"
		hash2 = "aeb94064af2a6107a14fd32f39cb502e704cd0ab"
		hash3 = "c2005c8d1a79da5e02e6a15d00151018658c264c"
		hash4 = "98223d4ec272d3a631498b621618d875dd32161d"

	strings:
		$x1 = "ZwGetWriteWatch" fullword ascii
		$x2 = "OutputDebugStringA" fullword ascii
		$x3 = "malwar" fullword ascii
		$x4 = "sampl" fullword ascii
		$x5 = "viru" fullword ascii
		$x6 = "sandb" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5MB and all of them
}
