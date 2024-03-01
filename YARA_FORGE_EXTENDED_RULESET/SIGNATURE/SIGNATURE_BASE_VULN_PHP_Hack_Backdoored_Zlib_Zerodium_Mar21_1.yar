rule SIGNATURE_BASE_VULN_PHP_Hack_Backdoored_Zlib_Zerodium_Mar21_1 : FILE
{
	meta:
		description = "Detects backdoored PHP zlib version"
		author = "Florian Roth (Nextron Systems)"
		id = "5e0ab8f8-776a-52b0-b5be-ff1d34bccfd1"
		date = "2021-03-29"
		modified = "2023-12-05"
		reference = "https://www.bleepingcomputer.com/news/security/phps-git-server-hacked-to-add-backdoors-to-php-source-code/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/vul_php_zlib_backdoor.yar#L2-L15"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "74bfd9e12cb7671cde953d361a2adeb9388edd9b2aab0f9ce04dce0d433561dc"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$x1 = "REMOVETHIS: sold to zerodium, mid 2017" fullword ascii
		$x2 = "HTTP_USER_AGENTT" ascii fullword

	condition:
		filesize <3000KB and all of them
}
