rule SIGNATURE_BASE_Sincap_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file Sincap.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "8c4dc7b1-94ce-5528-8442-eae05d2c9980"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4614-L4626"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "b68b90ff6012a103e57d141ed38a7ee9"
		logic_hash = "e708a7dcb26ff7d0208c1f092e14e701f2ae94c4ffca019f13064bbe04ef74d7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "$baglan=fopen(\"/tmp/$ekinci\",'r');"
		$s2 = "$tampon4=$tampon3-1"
		$s3 = "@aventgrup.net"

	condition:
		2 of them
}
