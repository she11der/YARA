import "pe"

rule SIGNATURE_BASE_MAL_SUSP_RANSOM_Lazy_Ransomnote_Feb24
{
	meta:
		description = "Detects the Lazy ransom note file 'HowToRestoreYourFiles.txt' which is a sign of a Lazy ransomware infection"
		author = "Florian Roth"
		id = "287dfd67-8d0d-5906-b593-3af42a5a3aa4"
		date = "2024-02-23"
		modified = "2024-02-23"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L145-L156"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "c9416d05f0bd9aab9d6108380c1b5364f4c4e112b6e0726202f083eaacfdcf56"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "All Encrypted files can be reversed to original form and become usable"

	condition:
		1 of them
}
