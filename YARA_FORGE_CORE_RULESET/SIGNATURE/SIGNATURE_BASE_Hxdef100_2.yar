rule SIGNATURE_BASE_Hxdef100_2
{
	meta:
		description = "Webshells Auto-generated - file hxdef100.exe"
		author = "Florian Roth (Nextron Systems)"
		id = "1f079b73-29de-50cf-868c-1639a43e576f"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L8202-L8215"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "1b393e2e13b9c57fb501b7cd7ad96b25"
		logic_hash = "d44131f6c1bfdc36079f474832a79a361dfad96d1b84f7004d682150c93eccc5"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "\\\\.\\mailslot\\hxdef-rkc000"
		$s2 = "Shared Components\\On Access Scanner\\BehaviourBlo"
		$s6 = "SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\"

	condition:
		all of them
}
