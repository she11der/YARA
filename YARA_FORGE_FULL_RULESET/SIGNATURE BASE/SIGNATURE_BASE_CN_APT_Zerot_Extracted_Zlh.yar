rule SIGNATURE_BASE_CN_APT_Zerot_Extracted_Zlh : FILE
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT - file Zlh.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "4c8b9a90-6cb3-5aba-a993-f73207341d0e"
		date = "2017-02-04"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cn_pp_zerot.yar#L225-L241"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "26796f75a8302bd6c93eb3ea43d0491b86770b52bd11aad6e1e250d968a77004"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "711f0a635bbd6bf1a2890855d0bd51dff79021db45673541972fe6e1288f5705"

	strings:
		$s1 = "nflogger.dll" fullword wide
		$s2 = "%s %d: CreateProcess('%s', '%s') failed. Windows error code is 0x%08x" fullword ascii
		$s3 = "_StartZlhh(): Executed \"%s\"" ascii
		$s4 = "Executable: '%s' (%s) %i" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 3 of them )
}
