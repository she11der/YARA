rule SIGNATURE_BASE_UACME_Akagi_2 : FILE
{
	meta:
		description = "Detects Windows User Account Control Bypass - from files Akagi32.exe, Akagi64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1177d663-1081-5d17-9dd7-1218d95d90f7"
		date = "2017-02-03"
		modified = "2023-12-05"
		reference = "https://github.com/hfiref0x/UACME"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/exploit_uac_elevators.yar#L151-L174"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "f79a82d466f51c86a0e6fb89688708c35dbcc7ba8f4543e5fb7565d41dd3faab"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "caf744d38820accb48a6e50216e547ed2bb3979604416dbcfcc991ce5e18f4ca"
		hash2 = "609e9b15114e54ffc40c05a8980cc90f436a4a77c69f3e32fe391c0b130ff1c5"

	strings:
		$x1 = "Usage: Akagi.exe [Method] [OptionalParamToExecute]" fullword wide
		$x2 = "[UCM] Target file already exists, abort" fullword wide
		$s1 = "MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options" fullword wide
		$s2 = "Akagi.exe" fullword wide
		$s3 = "Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}" fullword wide
		$s4 = "/c wusa %ws /extract:%%windir%%\\system32\\sysprep" fullword wide
		$s5 = "/c wusa %ws /extract:%%windir%%\\system32\\migwiz" fullword wide
		$s6 = "loadFrom=\"%systemroot%\\system32\\sysprep\\cryptbase.DLL\"" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*) or 3 of ($s*))) or (6 of them )
}
