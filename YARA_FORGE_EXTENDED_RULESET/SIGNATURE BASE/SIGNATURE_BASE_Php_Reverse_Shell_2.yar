rule SIGNATURE_BASE_Php_Reverse_Shell_2 : FILE
{
	meta:
		description = "Laudanum Injector Tools - file php-reverse-shell.php"
		author = "Florian Roth (Nextron Systems)"
		id = "f10cc33e-0cb6-5d08-af1f-5ef76368de9d"
		date = "2015-06-22"
		modified = "2023-12-05"
		reference = "http://laudanum.inguardians.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_laudanum_webshells.yar#L298-L312"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		hash = "025db3c3473413064f0606d93d155c7eb5049c42"
		logic_hash = "695dc565c273ed358f7d56526fa4956ba13b216d8897d0707e1660a82b745081"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$process = proc_open($shell, $descriptorspec, $pipes);" fullword ascii
		$s7 = "$shell = 'uname -a; w; id; /bin/sh -i';" fullword ascii

	condition:
		filesize <10KB and all of them
}
