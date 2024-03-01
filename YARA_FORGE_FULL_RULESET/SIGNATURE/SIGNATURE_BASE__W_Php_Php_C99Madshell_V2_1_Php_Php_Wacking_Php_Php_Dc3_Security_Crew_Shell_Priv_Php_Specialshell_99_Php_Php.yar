rule SIGNATURE_BASE__W_Php_Php_C99Madshell_V2_1_Php_Php_Wacking_Php_Php_Dc3_Security_Crew_Shell_Priv_Php_Specialshell_99_Php_Php
{
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "d22c4cc3-842b-5a24-bf4b-a8024b447b9e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L5414-L5430"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "7a4c74912caa1855efc3a2ea7fa6d0082f62776d77a211e59f12892d4883f240"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "433706fdc539238803fd47c4394b5109"
		hash4 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = " if ($mode & 0x200) {$world[\"execute\"] = ($world[\"execute\"] == \"x\")?\"t\":"
		$s1 = " $group[\"execute\"] = ($mode & 00010)?\"x\":\"-\";" fullword

	condition:
		all of them
}
