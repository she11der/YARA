rule SIGNATURE_BASE_RAT_Netwire
{
	meta:
		description = "Detects NetWire RAT"
		author = "Kevin Breen <kevin@techanarchy.net> & David Cannings"
		id = "f0077e8c-3e6a-5a98-9171-b0d81f24d27a"
		date = "2014-01-04"
		modified = "2023-12-05"
		reference = "http://malwareconfig.com/stats/NetWire"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_rats_malwareconfig.yar#L547-L569"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "6a4e757262c02dfe46ac28940b53a5695df2d242ccd4c16b42fbfdcf96072e91"
		score = 75
		quality = 60
		tags = ""
		maltype = "Remote Access Trojan"
		filetype = "exe"

	strings:
		$exe1 = "%.2d-%.2d-%.4d"
		$exe2 = "%s%.2d-%.2d-%.4d"
		$exe3 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
		$exe4 = "wcnwClass"
		$exe5 = "[Ctrl+%c]"
		$exe6 = "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
		$exe7 = "%s\\.purple\\accounts.xml"

	condition:
		all of them
}
