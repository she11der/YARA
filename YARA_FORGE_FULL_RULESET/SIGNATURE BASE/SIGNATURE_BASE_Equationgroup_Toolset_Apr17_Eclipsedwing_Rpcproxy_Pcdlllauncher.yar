rule SIGNATURE_BASE_Equationgroup_Toolset_Apr17_Eclipsedwing_Rpcproxy_Pcdlllauncher : FILE
{
	meta:
		description = "Detects EquationGroup Tool - April Leak"
		author = "Florian Roth (Nextron Systems)"
		id = "8dd15424-e1b5-5543-97d5-3b3a83faa428"
		date = "2017-04-15"
		modified = "2023-12-05"
		reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L1502-L1519"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8a01ea872c161521301182b922ece893f9ad1a33d902ec94963946f3b07d7266"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "48251fb89c510fb3efa14c4b5b546fbde918ed8bb25f041a801e3874bd4f60f8"
		hash2 = "237c22f4d43fdacfcbd6e1b5f1c71578279b7b06ea8e512b4b6b50f10e8ccf10"
		hash3 = "79a584c127ac6a5e96f02a9c5288043ceb7445de2840b608fc99b55cf86507ed"

	strings:
		$x1 = "[-] Failed to Prepare Payload!" fullword ascii
		$x2 = "ShellcodeStartOffset" fullword ascii
		$x3 = "[*] Waiting for AuthCode from exploit" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <100KB and 1 of them )
}
