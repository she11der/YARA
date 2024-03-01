rule SIGNATURE_BASE_Multiple_Php_Webshells_2
{
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L5447-L5467"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "26fe586ba7f4d1931b2df81aa27543ff422e699fd56b6b1be289a0f8d6954691"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "9e9ae0332ada9c3797d6cee92c2ede62"
		hash5 = "6cd50a14ea0da0df6a246a60c8f6f9c9"
		hash6 = "09609851caa129e40b0d56e90dfc476c"
		hash7 = "671cad517edd254352fe7e0c7c981c39"

	strings:
		$s0 = "elseif (!empty($ft)) {echo \"<center><b>Manually selected type is incorrect. I"
		$s1 = "else {echo \"<center><b>Unknown extension (\".$ext.\"), please, select type ma"
		$s3 = "$s = \"!^(\".implode(\"|\",$tmp).\")$!i\";" fullword

	condition:
		all of them
}
