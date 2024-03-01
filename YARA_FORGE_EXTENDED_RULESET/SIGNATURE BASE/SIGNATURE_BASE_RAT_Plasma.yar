rule SIGNATURE_BASE_RAT_Plasma
{
	meta:
		description = "Detects Plasma RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "2a19c0de-0078-5487-869c-1bcabea57300"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/Plasma"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/gen_rats_malwareconfig.yar#L625-L649"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "e73348d379c483a7917cf765a457739aed6940f180272fa8d0c0dd1eb8e5f562"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a = "Miner: Failed to Inject." wide
		$b = "Started GPU Mining on:" wide
		$c = "BK: Hard Bot Killer Ran Successfully!" wide
		$d = "Uploaded Keylogs Successfully!" wide
		$e = "No Slowloris Attack is Running!" wide
		$f = "An ARME Attack is Already Running on" wide
		$g = "Proactive Bot Killer Enabled!" wide
		$h = "PlasmaRAT" wide ascii
		$i = "AntiEverything" wide ascii

	condition:
		all of them
}
