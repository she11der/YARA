rule SIGNATURE_BASE_Php_Include_W_Shell_Php
{
	meta:
		description = "Semi-Auto-generated  - file php-include-w-shell.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "ddcf9031-2ec8-5a86-8326-60e4a699f494"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4783-L4794"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "4e913f159e33867be729631a7ca46850"
		logic_hash = "a63910d97b7ef447b2cadb7de12943d3dbb6eada27d3097b8acf58d9b65b6f60"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "$dataout .= \"<td><a href='$MyLoc?$SREQ&incdbhost=$myhost&incdbuser=$myuser&incd"
		$s1 = "if($run == 1 && $phpshellapp && $phpshellhost && $phpshellport) $strOutput .= DB"

	condition:
		1 of them
}
