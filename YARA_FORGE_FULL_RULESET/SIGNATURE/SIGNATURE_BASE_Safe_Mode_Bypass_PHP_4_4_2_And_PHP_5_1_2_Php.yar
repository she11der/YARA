rule SIGNATURE_BASE_Safe_Mode_Bypass_PHP_4_4_2_And_PHP_5_1_2_Php
{
	meta:
		description = "Semi-Auto-generated  - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "3e81f628-31b4-5c22-943e-62c8cb4c0c4d"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4459-L4471"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "49ad9117c96419c35987aaa7e2230f63"
		logic_hash = "d6d2a3999f2e8ceb70f57697c0a845edbbcfce0aba151ec6a0ac23f55265cd47"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Welcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy"
		$s1 = "Mode Shell v1.0</font></span>"
		$s2 = "has been already loaded. PHP Emperor <xb5@hotmail."

	condition:
		1 of them
}
