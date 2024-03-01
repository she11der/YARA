rule SIGNATURE_BASE_Php_Reverse_Shell : FILE
{
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "306d150f-95a8-57fd-8f5e-786c429af6b3"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L158-L173"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "3ef03bbe3649535a03315dcfc1a1208a09cea49d"
		logic_hash = "ea8e320abb57e0467db92271f7d36f144f85e04ce15cd9fa8d3f53dfa8d43929"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
		$s2 = "printit(\"Successfully opened reverse shell to $ip:$port\");" fullword ascii
		$s3 = "$input = fread($pipes[1], $chunk_size);" fullword ascii

	condition:
		filesize <15KB and all of them
}
