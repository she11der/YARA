rule SIGNATURE_BASE_CN_Honker_Arp_EMP_V1_0 : FILE
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Arp EMP v1.0.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "03782e94-4fac-529f-b235-19cdb124d53b"
		date = "2015-06-23"
		modified = "2023-12-05"
		reference = "Disclosed CN Honker Pentest Toolset"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/cn_pentestset_tools.yar#L897-L911"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "ae4954c142ad1552a2abaef5636c7ef68fdd99ee"
		logic_hash = "457035b1685ac7f1bdccaab0b64bb1ad3ca1bf5e0747222347ced2a11b9b9504"
		score = 70
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Arp EMP v1.0.exe" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
