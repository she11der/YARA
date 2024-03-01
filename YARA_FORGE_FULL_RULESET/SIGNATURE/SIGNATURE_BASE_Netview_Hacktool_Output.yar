import "pe"

rule SIGNATURE_BASE_Netview_Hacktool_Output
{
	meta:
		description = "Network domain enumeration tool output - often used by attackers - file filename.txt"
		author = "Florian Roth (Nextron Systems)"
		id = "259db870-6293-5a55-b56a-f981c060c18f"
		date = "2016-03-07"
		modified = "2023-12-05"
		reference = "https://github.com/mubix/netview"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3109-L3124"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "38a51e583b1485bdb29400cb9d0a73ec4d5387675779f949572d2b4d74da4230"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "[*] Using interval:" fullword
		$s2 = "[*] Using jitter:" fullword
		$s3 = "[+] Number of hosts:" fullword

	condition:
		2 of them
}
