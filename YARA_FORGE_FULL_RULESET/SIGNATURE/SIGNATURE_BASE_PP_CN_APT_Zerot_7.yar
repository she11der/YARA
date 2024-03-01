rule SIGNATURE_BASE_PP_CN_APT_Zerot_7 : FILE
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "e9cdca86-84a8-5673-935c-c319b523674b"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cn_pp_zerot.yar#L113-L129"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "87ab6cd5c769e7e38bef807fa7d15af3a66fed8fdb7fed49fa62d87e1049ceb4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "fc2d47d91ad8517a4a974c4570b346b41646fac333d219d2f1282c96b4571478"

	strings:
		$s1 = "RasTls.dll" fullword ascii
		$s2 = "RasTls.exe" fullword ascii
		$s4 = "LOADER ERROR" fullword ascii
		$s5 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
