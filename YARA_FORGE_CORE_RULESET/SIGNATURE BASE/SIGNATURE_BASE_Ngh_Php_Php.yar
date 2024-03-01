rule SIGNATURE_BASE_Ngh_Php_Php
{
	meta:
		description = "Semi-Auto-generated  - file ngh.php.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "2d8ff3c1-d6b3-57ce-8213-232b376dbd05"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L3737-L3751"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "c372b725419cdfd3f8a6371cfeebc2fd"
		logic_hash = "c794b216bafdaecf5bd138cc8c7552efbb8c3c571a441489d02a19793a4c294f"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "Cr4sh_aka_RKL"
		$s1 = "NGH edition"
		$s2 = "/* connectback-backdoor on perl"
		$s3 = "<form action=<?=$script?>?act=bindshell method=POST>"
		$s4 = "$logo = \"R0lGODlhMAAwAOYAAAAAAP////r"

	condition:
		1 of them
}
