rule SIGNATURE_BASE_Ak74Shell_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file ak74shell.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "eaf243cb-fa26-5f34-a724-60a08acff636"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4039-L4051"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "7f83adcb4c1111653d30c6427a94f66f"
		logic_hash = "64eb7e72679fc9ee81af6f46d0ab604357710716b93b1ddfaebc5596c968fce8"
		score = 75
		quality = 60
		tags = ""

	strings:
		$s1 = "$res .= '<td align=\"center\"><a href=\"'.$xshell.'?act=chmod&file='.$_SESSION["
		$s2 = "AK-74 Security Team Web Site: www.ak74-team.net"
		$s3 = "$xshell"

	condition:
		2 of them
}
