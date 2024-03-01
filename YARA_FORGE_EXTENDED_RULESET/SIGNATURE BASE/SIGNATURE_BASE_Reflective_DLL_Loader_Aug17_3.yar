import "pe"

rule SIGNATURE_BASE_Reflective_DLL_Loader_Aug17_3 : FILE
{
	meta:
		description = "Detects Reflective DLL Loader"
		author = "Florian Roth (Nextron Systems)"
		id = "91842f58-5205-533d-9e97-a1e84fbf259d"
		date = "2017-08-20"
		modified = "2022-12-21"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_loaders.yar#L130-L154"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "4fbba94e6d3dc7b4976c90c0f95683c548f3c444bf5eaf0a7c55d96150978a67"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d10e4b3f1d00f4da391ac03872204dc6551d867684e0af2a4ef52055e771f474"

	strings:
		$s1 = "\\Release\\inject.pdb" ascii
		$s2 = "!!! Failed to gather information on system processes! " fullword ascii
		$s3 = "reflective_dll.dll" fullword ascii
		$s4 = "[-] %s. Error=%d" fullword ascii
		$s5 = "\\Start Menu\\Programs\\reflective_dll.dll" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and (pe.imphash()=="26ba48d3e3b964f75ff148b6679b42ec" or 2 of them )) or (3 of them )
}
