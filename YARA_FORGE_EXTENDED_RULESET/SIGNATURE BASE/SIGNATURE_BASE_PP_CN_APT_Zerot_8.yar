rule SIGNATURE_BASE_PP_CN_APT_Zerot_8 : FILE
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "f9a4f092-c699-5e91-9667-64ffe1b02bc1"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_cn_pp_zerot.yar#L131-L147"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "a1d5e72970919cd5c0493f8882cbc6fb1bb3c5b6517813a4022efd0028dfe728"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4ef91c17b1415609a2394d2c6c353318a2503900e400aab25ab96c9fe7dc92ff"

	strings:
		$s1 = "/svchost.exe" fullword ascii
		$s2 = "RasTls.dll" fullword ascii
		$s3 = "20160620.htm" fullword ascii
		$s4 = "/20160620.htm" fullword ascii

	condition:
		( uint16(0)==0x5449 and filesize <1000KB and 3 of them )
}
