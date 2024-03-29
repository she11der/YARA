import "pe"

rule SIGNATURE_BASE_WPR_Windowspasswordrecovery_EXE_64 : FILE
{
	meta:
		description = "Windows Password Recovery - file ast64.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "0f6c7695-e616-5757-b9cd-8cff5f972c3e"
		date = "2017-03-15"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L3605-L3622"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6cdd46609d401b7c12b936de7f64bab0bc45b9d2c6079fae45a96f5be6857b82"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "4e1ea81443b34248c092b35708b9a19e43a1ecbdefe4b5180d347a6c8638d055"

	strings:
		$s1 = "%B %d %Y  -  %H:%M:%S" fullword wide
		$op0 = { 48 8d 8c 24 50 22 00 00 e8 bf eb ff ff 4c 8b c7 }
		$op1 = { ff 15 16 25 01 00 f7 d8 1b }
		$op2 = { e8 c2 26 00 00 83 20 00 83 c8 ff 48 8b 5c 24 30 }

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
