import "pe"

rule SIGNATURE_BASE_SUSP_Command_Line_Combos_Feb24_2 : SCRIPT FILE
{
	meta:
		description = "Detects suspicious command line combinations often found in post exploitation activities"
		author = "Florian Roth"
		id = "d9bc6083-c3ca-5639-a9df-483fea6d0187"
		date = "2024-02-23"
		modified = "2024-02-23"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L102-L114"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "0cd7b4771aa8fd622e873c5cdc6689d24394e5faf026b36d5f228ac09f4e0441"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$sa1 = " | iex"
		$sa2 = "iwr -UseBasicParsing "

	condition:
		filesize <2MB and all of them
}
