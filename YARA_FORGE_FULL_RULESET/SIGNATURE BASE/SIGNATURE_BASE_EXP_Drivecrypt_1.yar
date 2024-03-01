rule SIGNATURE_BASE_EXP_Drivecrypt_1 : FILE
{
	meta:
		description = "Detects DriveCrypt exploit"
		author = "Florian Roth (Nextron Systems)"
		id = "c192ca53-1de3-5d2d-a216-47e534ff4d01"
		date = "2018-08-21"
		modified = "2023-12-05"
		reference = "Internal Research"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/vul_drivecrypt.yar#L2-L17"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "1959f2e4838e40f2abc26ee16b03089088c96cafb101125bdc346f69fe76d7a4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "0dd09bc97c768abb84d0fb6d1ae7d789f1f83bfb2ce93ff9ff3c538dc1effa33"

	strings:
		$s1 = "x64passldr.exe" fullword ascii
		$s2 = "DCR.sys" fullword ascii
		$s3 = "amd64\\x64pass.sys" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <700KB and 2 of them
}
