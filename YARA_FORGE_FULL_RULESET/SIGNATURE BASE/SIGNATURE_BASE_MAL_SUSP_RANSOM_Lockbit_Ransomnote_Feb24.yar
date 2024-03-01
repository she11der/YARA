import "pe"

rule SIGNATURE_BASE_MAL_SUSP_RANSOM_Lockbit_Ransomnote_Feb24
{
	meta:
		description = "Detects the LockBit ransom note file 'LockBit-DECRYPT.txt' which is a sign of a LockBit ransomware infection"
		author = "Florian Roth"
		id = "b2fcb2a7-49e8-520c-944f-6acd5ded579b"
		date = "2024-02-23"
		modified = "2024-02-23"
		reference = "https://www.huntress.com/blog/slashandgrab-screen-connect-post-exploitation-in-the-wild-cve-2024-1709-cve-2024-1708"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/expl_connectwise_screenconnect_vuln_feb24.yar#L132-L143"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1fe07c33de1971b1f9430851dec4b8cd9f3ac7f087f0de18a2da4a390891b674"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = ">>>> Your personal DECRYPTION ID:"

	condition:
		1 of them
}
