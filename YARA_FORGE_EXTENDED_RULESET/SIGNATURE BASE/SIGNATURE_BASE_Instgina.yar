import "pe"

rule SIGNATURE_BASE_Instgina
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file InstGina.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "ccbda689-e61a-501d-a8ed-62e3c1c20289"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L2555-L2570"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5317fbc39508708534246ef4241e78da41a4f31c"
		logic_hash = "a55a13ced122b9901f0505d585e7a7c984d4231b3507282c1b15ff400ce51265"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "To Open Registry" fullword ascii
		$s4 = "I love Candy very much!!" ascii
		$s5 = "GinaDLL" fullword ascii

	condition:
		all of them
}
