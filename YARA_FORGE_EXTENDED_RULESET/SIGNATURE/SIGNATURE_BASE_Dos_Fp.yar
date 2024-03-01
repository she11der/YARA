rule SIGNATURE_BASE_Dos_Fp : FILE
{
	meta:
		description = "Chinese Hacktool Set - file fp.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "f4427aab-50c3-5bb9-997a-75e162a83f8a"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1051-L1067"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "41d57d356098ff55fe0e1f0bcaa9317df5a2a45c"
		logic_hash = "cc09743269ee36862c95c9323ad271ca9b6c350cf25163d126fef0f86bc6f671"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "fpipe -l 53 -s 53 -r 80 192.168.1.101" fullword ascii
		$s2 = "FPipe.exe" fullword wide
		$s3 = "http://www.foundstone.com" fullword ascii
		$s4 = "%s %s port %d. Address is already in use" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <65KB and all of them
}
