rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Maze
{
	meta:
		description = "Detects files referencing identities associated with Maze ransomware"
		author = "ditekShen"
		id = "7cc11912-e5d2-5477-ab9b-0c470bb5e1d6"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L513-L521"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "46070d46c502837e5fb87d0fb75244a1a21e90b4e0ce4b73c408b8dc67fe1bcb"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "getmyfilesback@airmail.cc" ascii wide nocase

	condition:
		any of them
}
