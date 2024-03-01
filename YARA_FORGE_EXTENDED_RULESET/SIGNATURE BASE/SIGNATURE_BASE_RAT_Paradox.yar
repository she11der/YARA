rule SIGNATURE_BASE_RAT_Paradox
{
	meta:
		description = "Detects Paradox RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "2f1e6226-799b-54eb-a4a4-6c0f1bf561b4"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Paradox"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L601-L623"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "fef41262b78a497c65c7548c58d78ba8912725b28606fd9e99d1dbc19bdf7393"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "ParadoxRAT"
		$b = "Form1"
		$c = "StartRMCam"
		$d = "Flooders"
		$e = "SlowLaris"
		$f = "SHITEMID"
		$g = "set_Remote_Chat"

	condition:
		all of them
}
