rule SIGNATURE_BASE_Byloader
{
	meta:
		description = "Webshells Auto-generated - file byloader.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "24940e4b-06eb-548d-9e14-1a8f9c864bd3"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L7982-L7997"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "0f0d6dc26055653f5844ded906ce52df"
		logic_hash = "66c900e4bc771fb23d7623e57ad51edaa95696c2e31554720582f3e33a1b2e25"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "SYSTEM\\CurrentControlSet\\Services\\NtfsChk"
		$s1 = "Failure ... Access is Denied !"
		$s2 = "NTFS Disk Driver Checking Service"
		$s3 = "Dumping Description to Registry..."
		$s4 = "Opening Service .... Failure !"

	condition:
		all of them
}
