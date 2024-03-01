rule SIGNATURE_BASE_Molerats_Jul17_Sample_Dropper : FILE
{
	meta:
		description = "Detects Molerats sample dropper SFX - July 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "b4622373-b496-51de-abaa-caa665b558b3"
		date = "2017-07-07"
		modified = "2023-12-05"
		reference = "https://mymalwareparty.blogspot.de/2017/07/operation-desert-eagle.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_molerats_jul17.yar#L97-L112"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "b356d8dbca8f4d11dda976e7eb03c993d05af35d13113b8c85fb07531a0203dc"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "ad0b3ac8c573d84c0862bf1c912dba951ec280d31fe5b84745ccd12164b0bcdb"

	strings:
		$s1 = "Please remove %s from %s folder. It is unsecure to run %s until it is done." fullword wide
		$s2 = "sfxrar.exe" fullword ascii
		$s3 = "attachment.hta" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
