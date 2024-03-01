rule SIGNATURE_BASE_RAT_Darkcomet
{
	meta:
		description = "Detects DarkComet RAT"
		author = "Kevin Breen <kevin@techanarchy.net>"
		id = "e6fd0269-dd0c-58c0-a1a3-24c2aed916ee"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/DarkComet"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L256-L282"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "db139f754f89affc706e090a41bfcd30cf49f9d4e16ade89993ee170f92cf68b"
		score = 75
		quality = 85
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$a1 = "#BOT#URLUpdate"
		$a2 = "Command successfully executed!"
		$a3 = "MUTEXNAME" wide
		$a4 = "NETDATA" wide
		$b1 = "FastMM Borland Edition"
		$b2 = "%s, ClassID: %s"
		$b3 = "I wasn't able to open the hosts file"
		$b4 = "#BOT#VisitUrl"
		$b5 = "#KCMDDC"

	condition:
		all of ($a*) or all of ($b*)
}
