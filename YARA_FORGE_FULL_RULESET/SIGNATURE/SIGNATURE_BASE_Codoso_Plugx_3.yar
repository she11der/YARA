rule SIGNATURE_BASE_Codoso_Plugx_3 : FILE
{
	meta:
		description = "Detects Codoso APT PlugX Malware"
		author = "Florian Roth (Nextron Systems)"
		id = "55066812-3a8e-5099-afb4-ff7a59f1ccb2"
		date = "2016-01-30"
		modified = "2023-12-05"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_codoso.yar#L11-L27"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "74e1e83ac69e45a3bee78ac2fac00f9e897f281ea75ed179737e9b6fe39971e3"
		logic_hash = "51615c2583bb672f148f216e4856e7e346b17884f0740d69f6a24f08b594bda4"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "Cannot create folder %sDCRC failed in the encrypted file %s. Corrupt file or wrong password." fullword wide
		$s2 = "mcs.exe" fullword ascii
		$s3 = "McAltLib.dll" fullword ascii
		$s4 = "WinRAR self-extracting archive" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1200KB and all of them
}
