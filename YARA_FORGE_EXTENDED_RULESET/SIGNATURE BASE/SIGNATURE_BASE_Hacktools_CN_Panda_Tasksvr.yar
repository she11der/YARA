import "pe"

rule SIGNATURE_BASE_Hacktools_CN_Panda_Tasksvr
{
	meta:
		description = "Disclosed hacktool set - file tasksvr.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "5c85b382-551a-5e9e-9af8-d106cbe26f74"
		date = "2014-11-17"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1382-L1397"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
		logic_hash = "183708e525ec6676662b59a2a3c79f5113a80f2d5b3bd4713c74a536fe303b2d"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "Consys21.dll" fullword ascii
		$s4 = "360EntCall.exe" fullword wide
		$s15 = "Beijing1" fullword ascii

	condition:
		all of them
}
