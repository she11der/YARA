rule SIGNATURE_BASE_PP_CN_APT_Zerot_4 : FILE
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "b21961ee-d346-51d3-bacd-02554240162d"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cn_pp_zerot.yar#L61-L75"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8011497e7d061a9ebde06667e47b5cd9469a433e0be1401d70637e7ace8e8155"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a9519d2624a842d2c9060b64bb78ee1c400fea9e43d4436371a67cbf90e611b8"

	strings:
		$s1 = "Mcutil.dll" fullword ascii
		$s2 = "mcut.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
