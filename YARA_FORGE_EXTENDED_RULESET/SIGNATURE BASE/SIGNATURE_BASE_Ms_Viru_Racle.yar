rule SIGNATURE_BASE_Ms_Viru_Racle : FILE
{
	meta:
		description = "Chinese Hacktool Set - file racle.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "bdc78dcc-79e6-5516-bba2-54bf537eae38"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_cn_hacktools.yar#L1143-L1159"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "13116078fff5c87b56179c5438f008caf6c98ecb"
		logic_hash = "d36db04c6a62a72e9f3079d09aedc9056c0a5032b4594af4d02ba55373f8b6a4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "PsInitialSystemProcess @%p" fullword ascii
		$s1 = "PsLookupProcessByProcessId(%u) Failed" fullword ascii
		$s2 = "PsLookupProcessByProcessId(%u) => %p" fullword ascii
		$s3 = "FirstStage() Loaded, CurrentThread @%p Stack %p - %p" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <210KB and all of them
}
