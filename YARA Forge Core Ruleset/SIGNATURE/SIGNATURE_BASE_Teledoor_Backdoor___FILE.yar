rule SIGNATURE_BASE_Teledoor_Backdoor___FILE
{
	meta:
		description = "Detects the TeleDoor Backdoor as used in Petya Attack in June 2017"
		author = "Florian Roth (Nextron Systems)"
		id = "ba9b4415-427e-5a13-b743-bed225d86db8"
		date = "2017-07-05"
		modified = "2023-12-05"
		reference = "https://goo.gl/CpfJQQ"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/crime_teledoor.yar#L11-L31"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		logic_hash = "785360fa19a61a547309fc7a8968c94d4887be001c6a66b41c7adb9dcd13cb82"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		hash1 = "d462966166450416d6addd3bfdf48590f8440dd80fc571a389023b7c860ca3ac"
		hash2 = "f9d6fe8bd8aca6528dec7eaa9f1aafbecde15fd61668182f2ba8a7fc2b9a6740"
		hash3 = "2fd2863d711a1f18eeee5c7c82f2349c5d4e00465de9789da837fcdca4d00277"

	strings:
		$c1 = { 50 61 79 6C 6F 61 64 00 41 75 74 6F 50 61 79 6C 6F 61 64 }
		$c2 = { 52 75 6E 43 6D 64 00 44 75 6D 70 44 61 74 61 }
		$c3 = { 00 5A 76 69 74 57 65 62 43 6C 69 65 6E 74 45 78 74 00 4D 69 6E 49 6E 66 6F }

	condition:
		( uint16(0)==0x5a4d and filesize <15000KB and 2 of them )
}