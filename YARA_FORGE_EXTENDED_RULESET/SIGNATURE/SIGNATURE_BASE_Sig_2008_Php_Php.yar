rule SIGNATURE_BASE_Sig_2008_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file 2008.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "bfa3caa9-70a5-536b-a887-58427eee43df"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L4025-L4038"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3e4ba470d4c38765e4b16ed930facf2c"
		logic_hash = "a437dc3dc836e93c7a691f7a000c4a4ae574ba95b3a216394ba42538beb9c0f7"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Codz by angel(4ngel)"
		$s1 = "Web: http://www.4ngel.net"
		$s2 = "$admin['cookielife'] = 86400;"
		$s3 = "$errmsg = 'The file you want Downloadable was nonexistent';"

	condition:
		1 of them
}
