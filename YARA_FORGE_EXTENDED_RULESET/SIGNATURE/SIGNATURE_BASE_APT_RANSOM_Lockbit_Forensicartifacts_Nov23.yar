rule SIGNATURE_BASE_APT_RANSOM_Lockbit_Forensicartifacts_Nov23
{
	meta:
		description = "Detects patterns found in Lockbit TA attacks exploiting Citrixbleed vulnerability CVE 2023-4966"
		author = "Florian Roth"
		id = "04bde599-2a5b-5a33-a6f1-67d57a564946"
		date = "2023-11-22"
		modified = "2023-12-05"
		reference = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-325a"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_ransom_lockbit_citrixbleed_nov23.yar#L73-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "6ba1d47e2cac72143c4612c420777024f114afc007c7b15251a58819654aeff1"
		score = 75
		quality = 85
		tags = ""

	strings:
		$x1 = "taskkill /f /im sqlwriter.exe /im winmysqladmin.exe /im w3sqlmgr.exe"
		$x2 = " 1> \\\\127.0.0.1\\admin$\\__"

	condition:
		1 of ($x*)
}
