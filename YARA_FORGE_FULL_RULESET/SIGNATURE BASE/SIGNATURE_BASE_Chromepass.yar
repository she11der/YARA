rule SIGNATURE_BASE_Chromepass : FILE
{
	meta:
		description = "Detects a tool used by APT groups - file ChromePass.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "950b9761-bdfd-514b-90ea-a1454d35ce5a"
		date = "2016-09-08"
		modified = "2022-12-21"
		reference = "http://goo.gl/igxLyF"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_buckeye.yar#L51-L76"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "277b7cee2bf70b5141b6ee8a566f1d9bc5dc4555fc14c929d5255151ddca77dd"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "5ff43049ae18d03dcc74f2be4a870c7056f6cfb5eb636734cca225140029de9a"

	strings:
		$x1 = "\\Release\\ChromePass.pdb" ascii
		$x2 = "Windows Protect folder for getting the encryption keys" wide
		$x3 = "Chrome User Data folder where the password file is stored" wide
		$s1 = "Opera Software\\Opera Stable\\Login Data" fullword wide
		$s2 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" fullword wide
		$s3 = "Load the passwords from another Windows user or external drive: " fullword wide
		$s4 = "Chrome Passwords List!Select the windows profile folder" fullword wide
		$s5 = "Load the passwords of the current logged-on user" fullword wide
		$s6 = "Windows Login Password:" fullword wide
		$s7 = "SELECT origin_url, action_url, username_element, username_value, password_element, password_value, signon_realm, date_created fr" ascii
		$s8 = "Chrome Password Recovery" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <700KB and 1 of ($x*)) or (5 of them )
}
