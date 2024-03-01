rule SIGNATURE_BASE_Locky_Ransomware
{
	meta:
		description = "Detects Locky Ransomware (matches also on Win32/Kuluoz)"
		author = "Florian Roth (Nextron Systems) (with the help of binar.ly)"
		id = "ce61e01e-a9ce-54f4-bd2d-8acf1d5fbc30"
		date = "2016-02-17"
		modified = "2023-12-05"
		reference = "https://goo.gl/qScSrE"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_locky.yar#L8-L21"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "5e945c1d27c9ad77a2b63ae10af46aee7d29a6a43605a9bfbf35cebbcff184d8"
		logic_hash = "c7584ea39c4aceedeb0ea2952be6ff212461674175855274f1783eef80ffba86"
		score = 75
		quality = 85
		tags = ""

	strings:
		$o1 = { 45 b8 99 f7 f9 0f af 45 b8 89 45 b8 }
		$o2 = { 2b 0a 0f af 4d f8 89 4d f8 c7 45 }

	condition:
		all of ($o*)
}
