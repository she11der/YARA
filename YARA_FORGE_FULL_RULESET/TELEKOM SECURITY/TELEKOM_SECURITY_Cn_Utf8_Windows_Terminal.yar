rule TELEKOM_SECURITY_Cn_Utf8_Windows_Terminal : capability hacktool
{
	meta:
		description = "This is a (dirty) hack to display UTF-8 on Windows command prompt."
		author = "Thomas Barabosch, Deutsche Telekom Security"
		id = "a1beee71-c526-58fb-a255-dba55ef7535b"
		date = "2022-01-14"
		modified = "2023-12-12"
		reference = "https://www.bitdefender.com/files/News/CaseStudies/study/401/Bitdefender-PR-Whitepaper-FIN8-creat5619-en-EN.pdf"
		source_url = "https://github.com/telekom-security/malware_analysis//blob/bf832d97e8fd292ec5e095e35bde992a6462e71c/hacktools/hacktools.yar#L59-L71"
		license_url = "N/A"
		logic_hash = "4c91280c3d6d3b48c4ee11bf3d0c2baecee1368fbf3951c0a3bf386454c557cf"
		score = 40
		quality = 20
		tags = ""

	strings:
		$a = " chcp 65001 " ascii wide

	condition:
		$a
}
