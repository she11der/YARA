import "pe"

rule SIGNATURE_BASE_CN_Packed_Scanner : FILE
{
	meta:
		description = "Suspiciously packed executable"
		author = "Florian Roth (Nextron Systems)"
		id = "a11c4ee6-7244-5601-af26-a45f9fdc8e1b"
		date = "2014-06-10"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L494-L510"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
		logic_hash = "0d9178ec65029e4ce8d4c3cc28ebd041c612f3a48f095b60c7a4515de03cccf4"
		score = 40
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "kernel32.dll" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "__GetMainArgs" fullword ascii
		$s4 = "WS2_32.DLL" fullword ascii

	condition:
		all of them and filesize <180KB and filesize >70KB
}
