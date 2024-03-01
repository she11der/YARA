rule SIGNATURE_BASE_Explosive_UA : FILE
{
	meta:
		description = "Explosive Malware Embedded User Agent - Volatile Cedar APT http://goo.gl/HQRCdw"
		author = "Florian Roth (Nextron Systems)"
		id = "d88d5fd6-adf9-5ced-8b79-e47e3ffbde50"
		date = "2015-04-03"
		modified = "2023-12-05"
		reference = "http://goo.gl/HQRCdw"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_volatile_cedar.yar#L90-L104"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "9ed7fedcf9cda868803c8ace393e08709a747b909178e19cdbb1b116edbb82f9"
		score = 60
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$x1 = "Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.1; .NET CLR 2.0.50727)" fullword

	condition:
		$x1 and uint16(0)==0x5A4D
}
