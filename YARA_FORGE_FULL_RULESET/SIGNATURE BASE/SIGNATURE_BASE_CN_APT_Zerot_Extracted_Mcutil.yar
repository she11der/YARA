rule SIGNATURE_BASE_CN_APT_Zerot_Extracted_Mcutil : FILE
{
	meta:
		description = "Chinese APT by Proofpoint ZeroT RAT  - file Mcutil.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "c887d36b-8aeb-54f1-a683-727561723238"
		date = "2017-02-04"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cn_pp_zerot.yar#L205-L223"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "edb6000fd65d6593bd94842e60ec099c5a652d10005f81d17063dba1a2e267d2"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "266c06b06abbed846ebabfc0e683f5d20dadab52241bc166b9d60e9b8493b500"

	strings:
		$s1 = "LoaderDll.dll" fullword ascii
		$s2 = "QageBox1USER" fullword ascii
		$s3 = "xhmowl" fullword ascii
		$s4 = "?KEYKY" fullword ascii
		$s5 = "HH:mm:_s" fullword ascii
		$s6 = "=licni] has maX0t" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <90KB and 3 of them ) or ( all of them )
}
