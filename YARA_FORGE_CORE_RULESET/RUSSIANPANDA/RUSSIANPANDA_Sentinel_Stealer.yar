rule RUSSIANPANDA_Sentinel_Stealer
{
	meta:
		description = "Detects Sentinel Stealer"
		author = "RussianPanda"
		id = "8a221d7b-8fa6-53cd-a3e8-63cc67285186"
		date = "2024-01-19"
		modified = "2024-01-19"
		reference = "https://github.com/RussianPanda95/Yara-Rules"
		source_url = "https://github.com/RussianPanda95/Yara-Rules/blob/1a5f7fbf0094a17dcddaa74b56fb43a231b550af/SentinelStealer/sentinel_stealer.yar#L1-L14"
		license_url = "N/A"
		hash = "3a540a8a81c5a5b452f154d7875423a3"
		logic_hash = "b9d72848842ea4d26544633bb83fccd17239b28493bde3f73341eb2004d8ee0c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "Sentinel.SmallerEncryptedIcon" wide
		$s2 = "SentinelSteals" wide
		$s4 = "_CorExeMain"

	condition:
		all of them
}
