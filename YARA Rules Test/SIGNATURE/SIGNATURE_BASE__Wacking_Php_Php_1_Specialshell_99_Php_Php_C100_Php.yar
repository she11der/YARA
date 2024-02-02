rule SIGNATURE_BASE__Wacking_Php_Php_1_Specialshell_99_Php_Php_C100_Php
{
	meta:
		description = "Semi-Auto-generated  - from files wacking.php.php.txt, 1.txt, SpecialShell_99.php.php.txt, c100.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "3dac5550-598a-5a0f-95c3-2e0162a686ee"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5189-L5205"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0d32fc00ba2602a1140dc9030894bb9524c55b95c445a08f2bf6f8fc60108e64"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "9c5bb5e3a46ec28039e8986324e42792"
		hash1 = "44542e5c3e9790815c49d5f9beffbbf2"
		hash2 = "09609851caa129e40b0d56e90dfc476c"
		hash3 = "38fd7e45f9c11a37463c3ded1c76af4c"

	strings:
		$s0 = "if(eregi(\"./shbd $por\",$scan))"
		$s1 = "$_POST['backconnectip']"
		$s2 = "$_POST['backcconnmsg']"

	condition:
		1 of them
}