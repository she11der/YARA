rule SIGNATURE_BASE_Webshell_Php_Moon
{
	meta:
		description = "Web Shell - file moon.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L1936-L1951"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "2a2b1b783d3a2fa9a50b1496afa6e356"
		logic_hash = "4e26dbef647caee19a8707a067c228ba96bd986369e4c87c68964ae42c85b09a"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s2 = "echo '<option value=\"create function backshell returns string soname"
		$s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
		$s8 = "echo '<option value=\"select cmdshell(\\'net user "

	condition:
		2 of them
}
