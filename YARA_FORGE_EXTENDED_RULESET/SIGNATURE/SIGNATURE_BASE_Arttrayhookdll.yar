import "pe"

rule SIGNATURE_BASE_Arttrayhookdll
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "324561fc-024c-5583-aa25-6b13e9616898"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-hacktools.yar#L1556-L1570"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
		logic_hash = "e43cefdb11df870f4732e74782ecefb94c0a4850c4aa994e4fbc940f523d2434"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "ArtTrayHookDll.dll" fullword ascii
		$s7 = "?TerminateHook@@YAXXZ" fullword ascii

	condition:
		all of them
}
