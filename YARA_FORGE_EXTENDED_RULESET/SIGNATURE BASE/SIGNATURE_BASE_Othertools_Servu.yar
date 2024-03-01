rule SIGNATURE_BASE_Othertools_Servu : FILE
{
	meta:
		description = "Chinese Hacktool Set - file svu.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "b750d090-8726-5d21-98ba-6cb050cb7174"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L349-L365"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "5c64e6879a9746a0d65226706e0edc7a"
		logic_hash = "fda476bdcc0bb496331ca9f506a1221d401d8671d23f61f1b88219c688163169"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "MZKERNEL32.DLL" fullword ascii
		$s1 = "UpackByDwing@" fullword ascii
		$s2 = "GetProcAddress" fullword ascii
		$s3 = "WriteFile" fullword ascii

	condition:
		uint32(0)==0x454b5a4d and $s0 at 0 and filesize <50KB and all of them
}
