rule SIGNATURE_BASE_Antichat_Socks5_Server_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file Antichat Socks5 Server.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "35d0930c-ef07-5fd4-9d7a-c0d685f92339"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L4433-L4445"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cbe9eafbc4d86842a61a54d98e5b61f1"
		logic_hash = "d6b203561f95f431b3d2c241011ae08c05619d45c5900a28137481c029e8297e"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "$port = base_convert(bin2hex(substr($reqmessage[$id], 3+$reqlen+1, 2)), 16, 10);" fullword
		$s3 = "#   [+] Domain name address type"
		$s4 = "www.antichat.ru"

	condition:
		1 of them
}
