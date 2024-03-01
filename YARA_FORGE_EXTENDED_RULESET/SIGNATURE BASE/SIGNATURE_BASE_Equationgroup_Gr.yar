rule SIGNATURE_BASE_Equationgroup_Gr : FILE
{
	meta:
		description = "Equation Group hack tool set"
		author = "Florian Roth (Nextron Systems)"
		id = "9ec19323-85d5-5edf-99eb-b452c09b870a"
		date = "2017-04-09"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_eqgrp_apr17.yar#L1308-L1322"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6df2a36e51fbe23e090094a91da76ca881a65d7e129c6e428ffef13787f230bc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d3cd725affd31fa7f0e2595f4d76b09629918612ef0d0307bb85ade1c3985262"

	strings:
		$s1 = "if [ -f /tmp/tmpwatch ] ; then" fullword ascii
		$s2 = "echo \"bailing. try a different name\"" fullword ascii

	condition:
		( filesize <1KB and all of them )
}
