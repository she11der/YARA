rule SIGNATURE_BASE_Fuckphpshell_Php
{
	meta:
		description = "Semi-Auto-generated  - file fuckphpshell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "010db63b-ff72-5f97-8651-a1c7851471ff"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L3723-L3736"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "554e50c1265bb0934fcc8247ec3b9052"
		logic_hash = "0c993960b4ca880b818c7b7ba726479ed1c64c46ef8ca82d3c990d69ebe43f42"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "$succ = \"Warning! "
		$s1 = "Don`t be stupid .. this is a priv3 server, so take extra care!"
		$s2 = "\\*=-- MEMBERS AREA --=*/"
		$s3 = "preg_match('/(\\n[^\\n]*){' . $cache_lines . '}$/', $_SESSION['o"

	condition:
		2 of them
}
