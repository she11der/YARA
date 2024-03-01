import "pe"

rule SIGNATURE_BASE_Allthethings : FILE
{
	meta:
		description = "Detects AllTheThings"
		author = "Florian Roth (Nextron Systems)"
		id = "c3169ca7-3482-5d55-a1d9-6d1c01349922"
		date = "2017-07-27"
		modified = "2022-12-21"
		reference = "https://github.com/subTee/AllTheThings"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L3873-L3892"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0d6b961afb98cfaefe930a7bc246b3f087469b752a8d4abb62b2826418fdfd53"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5a0e9a9ce00d843ea95bd5333b6ab50cc5b1dbea648cc819cfe48482513ce842"

	strings:
		$x1 = "\\obj\\Debug\\AllTheThings.pdb" ascii
		$x2 = "AllTheThings.exe" fullword wide
		$x3 = "\\AllTheThings.dll" ascii
		$x4 = "Hello From Main...I Don't Do Anything" fullword wide
		$x5 = "I am a basic COM Object" fullword wide
		$x6 = "I shouldn't really execute either." fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <50KB and 1 of them )
}
