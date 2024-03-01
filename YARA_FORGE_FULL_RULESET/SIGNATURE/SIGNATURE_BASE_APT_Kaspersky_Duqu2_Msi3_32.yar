rule SIGNATURE_BASE_APT_Kaspersky_Duqu2_Msi3_32 : FILE
{
	meta:
		description = "Kaspersky APT Report - Duqu2 Sample"
		author = "Florian Roth (Nextron Systems)"
		id = "6cbea2e7-f406-57cf-b9c8-9d84b1480035"
		date = "2015-06-10"
		modified = "2023-12-05"
		reference = "https://goo.gl/7yKyOj"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_kaspersky_duqu2.yar#L136-L157"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "53d9ef9e0267f10cc10f78331a9e491b3211046b"
		logic_hash = "718223d1ff82ffa0f3204e0cdaf0d441ed133f1f069d9ba2eb818bd3445f63ca"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "ProcessUserAccounts" fullword ascii
		$s1 = "SELECT `UserName`, `Password`, `Attributes` FROM `CustomUserAccounts`" fullword wide
		$s2 = "SELECT `UserName` FROM `CustomUserAccounts`" fullword wide
		$s3 = "SELECT `Data` FROM `Binary` WHERE `Name`='CryptHash%i'" fullword wide
		$s4 = "msi3_32.dll" fullword wide
		$s5 = "RunDLL" fullword ascii
		$s6 = "MSI Custom Action v3" fullword wide
		$s7 = "msi3_32" fullword wide
		$s8 = "Operating System" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <72KB and all of them
}
