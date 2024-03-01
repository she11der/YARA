rule SIGNATURE_BASE_Equationgroup_Promptkill : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file promptkill"
		author = "Florian Roth (Nextron Systems)"
		id = "e0749b10-fa5a-5d73-86e1-e2008e121674"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L648-L662"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7b46161b8cbb9a539171349b3e2a58f8e5a48c344b6d99020b3e96da9c878771"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "b448204503849926be249a9bafbfc1e36ef16421c5d3cfac5dac91f35eeaa52d"

	strings:
		$x1 = "exec(\"xterm $xargs -e /current/tmp/promptkill.kid.$tag $pid\");" fullword ascii
		$x2 = "$xargs=\"-title \\\"Kill process $pid?\\\" -name \\\"Kill process $pid?\\\" -bg white -fg red -geometry 202x19+0+0\" ;" fullword ascii

	condition:
		filesize <250KB and 1 of them
}
