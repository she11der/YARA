import "pe"
import "math"

rule SIGNATURE_BASE_APT_APT29_NOBELIUM_Boombox_PDF_Masq_May21_1 : FILE
{
	meta:
		description = "Detects PDF documents as used by BoomBox as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		id = "bdfb9600-edda-5c8c-ab23-14fb71c8e647"
		date = "2021-05-27"
		modified = "2023-12-05"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_apt29_nobelium_may21.yar#L145-L164"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "8f1514648b2b797adfe3f8f5acb577c26707dfe1da942c9634be3d88a180a407"
		score = 70
		quality = 35
		tags = "FILE"

	strings:
		$ah1 = { 25 50 44 46 2d 31 2e 33 0a 25 }
		$af1 = { 0a 25 25 45 4f 46 0a }
		$fp1 = "endobj" ascii
		$fp2 = "endstream" ascii
		$fp3 = { 20 6F 62 6A 0A }

	condition:
		$ah1 at 0 and $af1 at ( filesize -7) and filesize <100KB and not 1 of ($fp*) and math.entropy(16, filesize )>7
}
