rule SIGNATURE_BASE_Wanncry_M_Vbs___FILE
{
	meta:
		description = "Detects WannaCry Ransomware VBS"
		author = "Florian Roth (Nextron Systems)"
		id = "a8f13bd2-984d-5c8c-ac53-7d442e222850"
		date = "2017-05-12"
		modified = "2023-12-05"
		reference = "https://goo.gl/HG2j5T"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_wannacry.yar#L68-L83"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "e4606834535b4cad2e0d4a9bf6519fc4d749422fa4920f91fed9147ccfdff090"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"

	strings:
		$x1 = ".TargetPath = \"C:\\@" ascii
		$x2 = ".CreateShortcut(\"C:\\@" ascii
		$s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii

	condition:
		( uint16(0)==0x4553 and filesize <1KB and all of them )
}