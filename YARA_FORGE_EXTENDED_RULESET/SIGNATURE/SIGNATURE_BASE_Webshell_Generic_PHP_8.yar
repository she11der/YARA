rule SIGNATURE_BASE_Webshell_Generic_PHP_8
{
	meta:
		description = "PHP Webshells Github Archive"
		author = "Florian Roth (Nextron Systems)"
		id = "40c6f69f-9963-5e4f-af44-041d47738519"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/thor-webshells.yar#L6814-L6833"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "346df2686c4d43b3210b07a30845477e057602500e67baba69b50c41e8d501fa"
		score = 75
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		super_rule = 1
		hash0 = "fc1ae242b926d70e32cdb08bbe92628bc5bd7f99"
		hash1 = "9ad55629c4576e5a31dd845012d13a08f1c1f14e"
		hash2 = "c4aa2cf665c784553740c3702c3bfcb5d7af65a3"

	strings:
		$s1 = "elseif ( $cmd==\"file\" ) { /* <!-- View a file in text --> */" fullword
		$s2 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
		$s3 = "/* I added this to ensure the script will run correctly..." fullword
		$s14 = "<!--    </form>   -->" fullword
		$s15 = "<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\">" fullword
		$s20 = "elseif ( $cmd==\"downl\" ) { /*<!-- Save the edited file back to a file --> */" fullword

	condition:
		3 of them
}
