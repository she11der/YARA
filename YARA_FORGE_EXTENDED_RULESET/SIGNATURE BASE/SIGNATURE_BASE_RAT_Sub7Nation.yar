rule SIGNATURE_BASE_RAT_Sub7Nation
{
	meta:
		description = "Detects Sub7Nation RAT"
		author = "Kevin Breen <kevin@techanarchy.net> (slightly modified by Florian Roth to improve performance)"
		id = "4f41d649-4a90-566b-bda8-0a288380aeaa"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Sub7Nation"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L892-L913"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "bd6c423cd5cb5a86b20e5e65ab460904548b8814c92ac65e497757bb79a27681"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "EnableLUA /t REG_DWORD /d 0 /f"
		$i = "HostSettings"
		$verSpecific1 = "sevane.tmp"
		$verSpecific2 = "cmd_.bat"
		$verSpecific3 = "a2b7c3d7e4"
		$verSpecific4 = "cmd.dll"

	condition:
		all of them
}
