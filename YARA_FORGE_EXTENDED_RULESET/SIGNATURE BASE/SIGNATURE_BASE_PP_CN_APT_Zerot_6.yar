rule SIGNATURE_BASE_PP_CN_APT_Zerot_6 : FILE
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		author = "Florian Roth (Nextron Systems)"
		id = "2e3bb4bd-5e20-56e7-a82b-d717d83eaeeb"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_cn_pp_zerot.yar#L97-L111"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "2de78012cc384211cef6c12817fd8cef9d93eef6de3197d0cfec64c1a8022ae3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "a16078c6d09fcfc9d6ff7a91e39e6d72e2d6d6ab6080930e1e2169ec002b37d3"

	strings:
		$s1 = "jGetgQ|0h9=" fullword ascii
		$s2 = "\\sfxrar32\\Release\\sfxrar.pdb"

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of them
}
