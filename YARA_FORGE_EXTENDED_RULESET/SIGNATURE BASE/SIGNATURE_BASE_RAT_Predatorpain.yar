rule SIGNATURE_BASE_RAT_Predatorpain
{
	meta:
		description = "Detects PredatorPain RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "c6670179-871d-5a57-983b-d77354e2ede9"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/PredatorPain"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L674-L702"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "917234f83f891ad00bd83908c244818f517ea89cf7d8c81cfc3618b8386c1804"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string1 = "holderwb.txt" wide
		$string3 = "There is a file attached to this email" wide
		$string4 = "screens\\screenshot" wide
		$string5 = "Disablelogger" wide
		$string6 = "\\pidloc.txt" wide
		$string7 = "clearie" wide
		$string8 = "clearff" wide
		$string9 = "emails should be sent to you shortly" wide
		$string10 = "jagex_cache\\regPin" wide
		$string11 = "open=Sys.exe" wide
		$ver1 = "PredatorLogger" wide
		$ver2 = "EncryptedCredentials" wide
		$ver3 = "Predator Pain" wide

	condition:
		7 of ($string*) and any of ($ver*)
}
