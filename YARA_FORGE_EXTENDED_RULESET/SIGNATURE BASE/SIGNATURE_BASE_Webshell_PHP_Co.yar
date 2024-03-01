rule SIGNATURE_BASE_Webshell_PHP_Co
{
	meta:
		description = "Web Shell - file co.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1726-L1740"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "62199f5ac721a0cb9b28f465a513874c"
		logic_hash = "3fab3e97d10b6c56fb7df8bcd520bda318fc127a620c5aafba09cb36ffd6a8df"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
		$s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword

	condition:
		all of them
}
