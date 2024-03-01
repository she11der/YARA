rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Lokilocker
{
	meta:
		description = "Detects files referencing identities associated with LokiLocker ransomware"
		author = "ditekShen"
		id = "ab2cf390-4544-54ed-913c-d463d0f1bdb0"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/yara/indicator_knownbad_id.yar#L523-L531"
		license_url = "https://github.com/ditekshen/detection/blob/c37b067259715d4c93ac274a0830c54b355556a1/LICENSE.txt"
		logic_hash = "1ab9a2ce7e39d916b389e2adb975e3558ddb7d87f7e9494e6b20cb25edd3cb84"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "Unlockpls.dr01@yahoo.com" ascii wide nocase

	condition:
		any of them
}
