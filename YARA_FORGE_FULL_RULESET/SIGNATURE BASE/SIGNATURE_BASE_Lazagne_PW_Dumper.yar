import "pe"

rule SIGNATURE_BASE_Lazagne_PW_Dumper
{
	meta:
		description = "Detects Lazagne PW Dumper"
		author = "Markus Neis / Florian Roth"
		id = "1904029e-9336-5278-ae2e-4bc853316600"
		date = "2018-03-22"
		modified = "2023-12-05"
		reference = "https://github.com/AlessandroZ/LaZagne/releases/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L4221-L4235"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "2eac81d5cecdaca7eeaa83be70a688a595f8bbf54679ee565ba325b9e384552b"
		score = 70
		quality = 85
		tags = ""

	strings:
		$s1 = "Crypto.Hash" fullword ascii
		$s2 = "laZagne" fullword ascii
		$s3 = "impacket.winregistry" fullword ascii

	condition:
		3 of them
}
