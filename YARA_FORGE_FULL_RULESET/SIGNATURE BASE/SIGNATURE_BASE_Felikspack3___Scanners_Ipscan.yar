import "pe"

rule SIGNATURE_BASE_Felikspack3___Scanners_Ipscan
{
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "8360b268-3434-5142-9248-40b7a1589be9"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L233-L245"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
		logic_hash = "8da10a4536ecea889f29bb3f098518580629bf48eda88db7adfc5f61738ede25"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s2 = "WCAP;}ECTED"
		$s4 = "NotSupported"
		$s6 = "SCAN.VERSION{_"

	condition:
		all of them
}
