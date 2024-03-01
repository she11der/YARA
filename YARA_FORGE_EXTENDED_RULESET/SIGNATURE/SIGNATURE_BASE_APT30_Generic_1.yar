rule SIGNATURE_BASE_APT30_Generic_1 : FILE
{
	meta:
		description = "FireEye APT30 Report Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "4d21f402-24da-5e38-9225-a1461e61802f"
		date = "2015-04-13"
		modified = "2023-12-05"
		reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_apt30_backspace.yar#L998-L1031"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "0a2d4e8583286a3f44b49dc902143ee1ea321d26275c6cbcd54876e94b8cd2a3"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "aaa5c64200ff0818c56ebe4c88bcc1143216c536"
		hash1 = "cb4263cab467845dae9fae427e3bbeb31c6a14c2"
		hash2 = "b69b95db8a55a050d6d6c0cba13d73975b8219ca"
		hash3 = "5c29e21bbe8873778f9363258f5e570dddcadeb9"
		hash4 = "d5cb07d178963f2dea2c754d261185ecc94e09d6"
		hash5 = "626dcdd7357e1f8329e9137d0f9883f57ec5c163"
		hash6 = "843997b36ed80d3aeea3c822cb5dc446b6bfa7b9"

	strings:
		$s0 = "%s\\%s.txt" fullword
		$s1 = "\\ldsysinfo.txt"
		$s4 = "(Extended Wansung)" fullword
		$s6 = "Computer Name:" fullword
		$s7 = "%s %uKB %04u-%02u-%02u %02u:%02u" fullword
		$s8 = "ASSAMESE" fullword
		$s9 = "BELARUSIAN" fullword
		$s10 = "(PR China)" fullword
		$s14 = "(French)" fullword
		$s15 = "AdvancedServer" fullword
		$s16 = "DataCenterServer" fullword
		$s18 = "(Finland)" fullword
		$s19 = "%s %04u-%02u-%02u %02u:%02u" fullword
		$s20 = "(Chile)" fullword

	condition:
		filesize <250KB and uint16(0)==0x5A4D and all of them
}
