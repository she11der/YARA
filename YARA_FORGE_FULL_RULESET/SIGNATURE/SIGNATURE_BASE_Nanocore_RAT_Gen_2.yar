rule SIGNATURE_BASE_Nanocore_RAT_Gen_2 : FILE
{
	meta:
		description = "Detetcs the Nanocore RAT"
		author = "Florian Roth (Nextron Systems)"
		id = "74124961-3b0e-5808-b495-90437d3a5999"
		date = "2016-04-22"
		modified = "2023-12-05"
		reference = "https://www.sentinelone.com/blogs/teaching-an-old-rat-new-tricks/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_nanocore_rat.yar#L28-L44"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "23b3d149012fb8395b7daa2ecaf3ee66fdeac352ac94d632d76e52df2c6e8ea6"
		score = 100
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "755f49a4ffef5b1b62f4b5a5de279868c0c1766b528648febf76628f1fe39050"

	strings:
		$x1 = "NanoCore.ClientPluginHost" fullword ascii
		$x2 = "IClientNetworkHost" fullword ascii
		$x3 = "#=qjgz7ljmpp0J7FvL9dmi8ctJILdgtcbw8JYUc6GC8MeJ9B11Crfg2Djxcf0p8PZGe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and 1 of them ) or ( all of them )
}
