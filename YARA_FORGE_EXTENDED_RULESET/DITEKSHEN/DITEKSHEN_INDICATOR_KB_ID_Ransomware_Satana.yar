rule DITEKSHEN_INDICATOR_KB_ID_Ransomware_Satana
{
	meta:
		description = "Detects files referencing identities associated with Satana ransomware"
		author = "ditekShen"
		id = "a362d4ca-d475-5392-a3ac-45337425d8e7"
		date = "2024-01-23"
		modified = "2024-01-23"
		reference = "https://github.com/ditekshen/detection"
		source_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/yara/indicator_knownbad_id.yar#L438-L447"
		license_url = "https://github.com/ditekshen/detection/blob/5fc671f9f4a5847c929d488dc74f8b671529b254/LICENSE.txt"
		logic_hash = "6d82e2497044518cee1b56da85f1ad6ac7934eec9ca68501932d55add4236d45"
		score = 75
		quality = 73
		tags = ""

	strings:
		$s1 = "adamadam@ausi.com" ascii wide nocase
		$s2 = "XsrR2he2Z8un5ysGWnJ1wveZRPRS96XEoX" ascii wide

	condition:
		any of them
}
