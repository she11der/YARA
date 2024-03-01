rule SIGNATURE_BASE_Apt_Equation_Equationlaser_Runtimeclasses
{
	meta:
		description = "Rule to detect the EquationLaser malware"
		author = "Kaspersky Lab"
		id = "924c80ca-3607-57aa-85a2-b33ff52b0c1b"
		date = "2015-02-16"
		modified = "2023-12-05"
		reference = "https://securelist.com/blog/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/spy_equation_fiveeyes.yar#L40-L57"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "663ea56f869f7099a92658df5bddd76d4e5ba8ac5dfc693733579682b9eee860"
		score = 75
		quality = 85
		tags = ""
		version = "1.0"

	strings:
		$a1 = "?a73957838_2@@YAXXZ"
		$a2 = "?a84884@@YAXXZ"
		$a3 = "?b823838_9839@@YAXXZ"
		$a4 = "?e747383_94@@YAXXZ"
		$a5 = "?e83834@@YAXXZ"
		$a6 = "?e929348_827@@YAXXZ"

	condition:
		any of them
}
