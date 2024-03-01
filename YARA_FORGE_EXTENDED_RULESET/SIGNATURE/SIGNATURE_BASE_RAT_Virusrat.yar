rule SIGNATURE_BASE_RAT_Virusrat
{
	meta:
		description = "Detects VirusRAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "ef00cec9-d09b-5010-8e7d-bb391c937f34"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/VirusRat"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L940-L967"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "8540296fe1341a793377494cec9ba6ee0313203bee9997f0da0b692959727c59"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$string0 = "virustotal"
		$string1 = "virusscan"
		$string2 = "abccba"
		$string3 = "pronoip"
		$string4 = "streamWebcam"
		$string5 = "DOMAIN_PASSWORD"
		$string6 = "Stub.Form1.resources"
		$string7 = "ftp://{0}@{1}" wide
		$string8 = "SELECT * FROM moz_logins" wide
		$string9 = "SELECT * FROM moz_disabledHosts" wide
		$string10 = "DynDNS\\Updater\\config.dyndns" wide
		$string11 = "|BawaneH|" wide

	condition:
		all of them
}
