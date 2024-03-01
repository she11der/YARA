rule SIGNATURE_BASE_B374K_Back_Connect : FILE
{
	meta:
		description = "Detects privilege escalation tool"
		author = "Florian Roth (Nextron Systems)"
		id = "8612bda2-2576-56c0-a4ba-afbef419ab05"
		date = "2016-08-18"
		modified = "2023-12-05"
		reference = "Internal Analysis"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_b374k_extra.yar#L8-L24"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "dd89aefb6c1add44bfe2a706cd161a16f36a649f910ace16b641a7836525aa73"
		score = 80
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "c8e16f71f90bbaaef27ccaabb226b43762ca6f7e34d7d5585ae0eb2d36a4bae5"

	strings:
		$s1 = "AddAtomACreatePro" fullword ascii
		$s2 = "shutdow" fullword ascii
		$s3 = "/config/i386" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <10KB and all of them )
}
