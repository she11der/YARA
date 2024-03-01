rule SIGNATURE_BASE_Equationgroup_Estopmoonlit : FILE
{
	meta:
		description = "Equation Group hack tool leaked by ShadowBrokers- file estopmoonlit"
		author = "Florian Roth (Nextron Systems)"
		id = "7ae7a8b7-5e27-5604-8c57-6d60ffa0fb72"
		date = "2017-04-08"
		modified = "2023-12-05"
		reference = "https://medium.com/@shadowbrokerss/dont-forget-your-base-867d304a94b1"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_eqgrp_apr17.yar#L683-L699"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "06293b6f48d2595f3426088cddc4b0c4d1ebc1de90fa640d5b5e806a45a2b6bd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "707ecc234ed07c16119644742ebf563b319b515bf57fd43b669d3791a1c5e220"

	strings:
		$x1 = "[+] shellcode prepared, re-executing" fullword ascii
		$x2 = "[-] kernel not vulnerable: prctl" fullword ascii
		$x3 = "[-] shell failed" fullword ascii
		$x4 = "[!] selinux apparently enforcing.  Continue [y|n]? " fullword ascii

	condition:
		filesize <250KB and 1 of them
}
