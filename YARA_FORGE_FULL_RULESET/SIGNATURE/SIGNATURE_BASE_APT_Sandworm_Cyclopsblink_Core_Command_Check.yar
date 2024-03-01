rule SIGNATURE_BASE_APT_Sandworm_Cyclopsblink_Core_Command_Check : FILE
{
	meta:
		description = "Detects the code bytes used to test the command ID being sent to the core component of Cyclops Blink"
		author = "NCSC"
		id = "46066474-7647-52fb-b40d-30ff8e285b6e"
		date = "2022-02-23"
		modified = "2023-12-05"
		reference = "https://www.ncsc.gov.uk/news/joint-advisory-shows-new-sandworm-malware-cyclops-blink-replaces-vpnfilter"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_sandworm_cyclops_blink.yar#L90-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "71c9da1f0e9e64be87293c985f2a4a59a6c87ffd127ce5104ebe95a0ccb316af"
		score = 50
		quality = 85
		tags = "FILE"
		hash1 = "3adf9a59743bc5d8399f67cab5eb2daf28b9b863"
		hash2 = "c59bc17659daca1b1ce65b6af077f86a648ad8a8"

	strings:
		$cmd_check = {81 3F 00 18 88 09 00 05 54 00 06 3E 2F 80 00 (07|0A|0B|0C|0D) }

	condition:
		( uint32(0)==0x464c457f) and (#cmd_check==5)
}
