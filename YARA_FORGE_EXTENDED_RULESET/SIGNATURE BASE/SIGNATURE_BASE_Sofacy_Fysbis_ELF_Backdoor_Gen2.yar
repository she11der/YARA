rule SIGNATURE_BASE_Sofacy_Fysbis_ELF_Backdoor_Gen2 : FILE
{
	meta:
		description = "Detects Sofacy Fysbis Linux Backdoor"
		author = "Florian Roth (Nextron Systems)"
		id = "d4e3a8bb-b23a-53a4-b5fb-b321a3417b43"
		date = "2016-02-13"
		modified = "2023-12-05"
		reference = "http://researchcenter.paloaltonetworks.com/2016/02/a-look-into-fysbis-sofacys-linux-backdoor/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_sofacy_fysbis.yar#L37-L55"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "1d50a789e9c43fce27f3ad390cbdd9533c61e4f263cec1aa1abfba6545e55c57"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "02c7cf55fd5c5809ce2dce56085ba43795f2480423a4256537bfdfda0df85592"
		hash2 = "8bca0031f3b691421cb15f9c6e71ce193355d2d8cf2b190438b6962761d0c6bb"
		hash3 = "fd8b2ea9a2e8a67e4cb3904b49c789d57ed9b1ce5bebfe54fe3d98214d6a0f61"

	strings:
		$s1 = "RemoteShell" ascii
		$s2 = "basic_string::_M_replace_dispatch" fullword ascii
		$s3 = "HttpChannel" ascii

	condition:
		uint16(0)==0x457f and filesize <500KB and all of them
}
