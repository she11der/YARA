rule SIGNATURE_BASE__W_Php_Php_C99Madshell_V2_1_Php_Php_Wacking_Php_Php_C99Shell_V1_0_Php_Php_Specialshell_99_Php_Php
{
	meta:
		description = "Semi-Auto-generated "
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "ce88027c-ae08-59f3-948d-6f3d58515468"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L5314-L5332"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "0f44dc1ff243b234a718e8dbd5cc8c4dc8eb9d3b63300a5c6ff72b86280607bf"
		score = 75
		quality = 85
		tags = ""
		super_rule = 1
		hash0 = "38a3f9f2aa47c2e940695f3dba6a7bb2"
		hash1 = "3ca5886cd54d495dc95793579611f59a"
		hash2 = "9c5bb5e3a46ec28039e8986324e42792"
		hash3 = "d8ae5819a0a2349ec552cbcf3a62c975"
		hash4 = "09609851caa129e40b0d56e90dfc476c"

	strings:
		$s0 = "c99ftpbrutecheck"
		$s1 = "$ftpquick_t = round(getmicrotime()-$ftpquick_st,4);" fullword
		$s2 = "$fqb_lenght = $nixpwdperpage;" fullword
		$s3 = "$sock = @ftp_connect($host,$port,$timeout);" fullword

	condition:
		2 of them
}
