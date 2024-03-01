rule SIGNATURE_BASE_PP_CN_APT_Zerot_1 : FILE
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "c16f3abb-ac7e-5d5f-b8d7-b105cff3886e"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cn_pp_zerot.yar#L11-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "ad3018e6aa377b5032b04226ecb1e27b2cc7bc8294455ea51e426b5182ed7821"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "09061c603a32ac99b664f7434febfc8c1f9fd7b6469be289bb130a635a6c47c0"

	strings:
		$s1 = "suprise.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and all of them )
}
